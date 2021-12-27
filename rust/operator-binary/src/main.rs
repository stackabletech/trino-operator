mod discovery;
mod utils;
mod trino_controller;


use std::str::FromStr;

use stackable_operator::{
    k8s_openapi::api::{
        apps::v1::StatefulSet,
        core::v1::{ConfigMap, Endpoints, Service},
    },
    kube::{
        self,
        api::{DynamicObject, ListParams},
        runtime::{
            controller::{Context, ReconcilerAction},
            reflector::ObjectRef,
            Controller,
        },
        CustomResourceExt, Resource,
    },
    product_config::ProductConfigManager,
};
use tokio::sync::futures;
use structopt::StructOpt;

mod built_info {
    include!(concat!(env!("OUT_DIR"), "/built.rs"));
}

pub const APP_NAME: &str = "trino";
pub const APP_PORT: u16 = 2181;

#[derive(StructOpt)]
#[structopt(about = built_info::PKG_DESCRIPTION, author = "Stackable GmbH - info@stackable.de")]
struct Opts {
    #[structopt(subcommand)]
    cmd: Cmd,
}

#[derive(StructOpt)]
enum Cmd {
    /// Print CRD objects
    Crd,
    /// Run operator
    Run {
        /// Provides the path to a product-config file
        #[structopt(long, short = "p", value_name = "FILE")]
        product_config: Option<String>,
    },
}

/// Erases the concrete types of the controller result, so that we can merge the streams of multiple controllers for different resources.
///
/// In particular, we convert `ObjectRef<K>` into `ObjectRef<DynamicObject>` (which carries `K`'s metadata at runtime instead), and
/// `E` into the trait object `anyhow::Error`.
fn erase_controller_result_type<K: Resource, E: std::error::Error + Send + Sync + 'static>(
    res: Result<(ObjectRef<K>, ReconcilerAction), E>,
) -> anyhow::Result<(ObjectRef<DynamicObject>, ReconcilerAction)> {
    let (obj_ref, action) = res?;
    Ok((obj_ref.erase(), action))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    stackable_operator::logging::initialize_logging("TRINO_OPERATOR_LOG");

    let opts = Opts::from_args();
    match opts.cmd {
        Cmd::Crd => println!(
            "{}{}",
            serde_yaml::to_string(&TrinoCluster::crd())?,
            serde_yaml::to_string(&TrinoCluster::crd())?
        ),
        Cmd::Run { product_config } => {
            stackable_operator::utils::print_startup_string(
                built_info::PKG_DESCRIPTION,
                built_info::PKG_VERSION,
                built_info::GIT_VERSION,
                built_info::TARGET,
                built_info::BUILT_TIME_UTC,
                built_info::RUSTC_VERSION,
            );
            let product_config = if let Some(product_config_path) = product_config {
                ProductConfigManager::from_yaml_file(&product_config_path)?
            } else {
                ProductConfigManager::from_str(include_str!(
                    "../../../deploy/config-spec/properties.yaml"
                ))?
            };
            let kube = kube::Client::try_default().await?;
            let trinos = kube::Api::<TrinoCluster>::all(kube.clone());
            let trino_controller_builder = Controller::new(trinos.clone(), ListParams::default());
            let trino_store = trino_controller_builder.store();
            let trino_controller = trino_controller_builder
                .owns(
                    kube::Api::<Service>::all(kube.clone()),
                    ListParams::default(),
                )
                .watches(
                    kube::Api::<Endpoints>::all(kube.clone()),
                    ListParams::default(),
                    move |endpoints| {
                        trino_store
                            .state()
                            .into_iter()
                            .filter(move |trino| {
                                trino.metadata.namespace == endpoints.metadata.namespace
                                    && trino.server_role_service_name() == endpoints.metadata.name
                            })
                            .map(|trino| ObjectRef::from_obj(&trino))
                    },
                )
                .owns(
                    kube::Api::<StatefulSet>::all(kube.clone()),
                    ListParams::default(),
                )
                .owns(
                    kube::Api::<ConfigMap>::all(kube.clone()),
                    ListParams::default(),
                )
                .run(
                    trino_controller::reconcile_zk,
                    trino_controller::error_policy,
                    Context::new(trino_controller::Ctx {
                        kube: kube.clone(),
                        product_config,
                    }),
                );
             futures::stream::select(
                trino_controller.map(erase_controller_result_type),
            )
            .for_each(|res| async {
                match res {
                    Ok((obj, _)) => tracing::info!(object = %obj, "Reconciled object"),
                    Err(err) => {
                        tracing::error!(
                            error = &*err as &dyn std::error::Error,
                            "Failed to reconcile object",
                        )
                    }
                }
            })
            .await;
        }
    }

    Ok(())
}
