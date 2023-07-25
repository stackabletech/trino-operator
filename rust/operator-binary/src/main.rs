mod authentication;
mod catalog;
mod command;
mod controller;
mod product_logging;

use crate::controller::{CONTROLLER_NAME, OPERATOR_NAME};

use clap::{crate_description, crate_version, Parser};
use futures::stream::StreamExt;
use stackable_operator::{
    cli::{Command, ProductOperatorRun},
    commons::authentication::AuthenticationClass,
    k8s_openapi::api::{
        apps::v1::StatefulSet,
        core::v1::{ConfigMap, Service},
    },
    kube::{
        runtime::{reflector::ObjectRef, watcher, Controller},
        ResourceExt,
    },
    logging::controller::report_controller_reconciled,
    CustomResourceExt,
};
use stackable_trino_crd::{catalog::TrinoCatalog, TrinoCluster, APP_NAME};
use std::sync::Arc;

mod built_info {
    include!(concat!(env!("OUT_DIR"), "/built.rs"));
    pub const TARGET_PLATFORM: Option<&str> = option_env!("TARGET");
}

#[derive(Parser)]
#[clap(about, author)]
struct Opts {
    #[clap(subcommand)]
    cmd: Command,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opts = Opts::parse();
    match opts.cmd {
        Command::Crd => {
            TrinoCluster::print_yaml_schema()?;
            TrinoCatalog::print_yaml_schema()?;
        }
        Command::Run(ProductOperatorRun {
            product_config,
            watch_namespace,
            tracing_target,
        }) => {
            stackable_operator::logging::initialize_logging(
                "TRINO_OPERATOR_LOG",
                APP_NAME,
                tracing_target,
            );
            stackable_operator::utils::print_startup_string(
                crate_description!(),
                crate_version!(),
                built_info::GIT_VERSION,
                built_info::TARGET_PLATFORM.unwrap_or("unknown target"),
                built_info::BUILT_TIME_UTC,
                built_info::RUSTC_VERSION,
            );
            let product_config = product_config.load(&[
                "deploy/config-spec/properties.yaml",
                "/etc/stackable/trino-operator/config-spec/properties.yaml",
            ])?;

            let client =
                stackable_operator::client::create_client(Some(OPERATOR_NAME.to_string())).await?;

            let cluster_controller = Controller::new(
                watch_namespace.get_api::<TrinoCluster>(&client),
                watcher::Config::default(),
            );
            let catalog_cluster_store = Arc::new(cluster_controller.store());
            let authentication_class_cluster_store = catalog_cluster_store.clone();

            cluster_controller
                .owns(
                    watch_namespace.get_api::<Service>(&client),
                    watcher::Config::default(),
                )
                .owns(
                    watch_namespace.get_api::<StatefulSet>(&client),
                    watcher::Config::default(),
                )
                .owns(
                    watch_namespace.get_api::<ConfigMap>(&client),
                    watcher::Config::default(),
                )
                .shutdown_on_signal()
                .watches(
                    watch_namespace.get_api::<TrinoCatalog>(&client),
                    watcher::Config::default(),
                    move |catalog| {
                        // TODO: Filter clusters more precisely based on the catalogLabelSelector to avoid unnecessary reconciles
                        catalog_cluster_store
                            .state()
                            .into_iter()
                            // Catalogs can only be referenced within namespaces
                            .filter(move |cluster| cluster.namespace() == catalog.namespace())
                            .map(|cluster| ObjectRef::from_obj(&*cluster))
                    },
                )
                .watches(
                    client.get_api::<AuthenticationClass>(&()),
                    watcher::Config::default(),
                    move |authentication_class| {
                        authentication_class_cluster_store
                            .state()
                            .into_iter()
                            .filter(move |trino: &Arc<TrinoCluster>| {
                                references_authentication_class(trino, &authentication_class)
                            })
                            .map(|trino| ObjectRef::from_obj(&*trino))
                    },
                )
                .run(
                    controller::reconcile_trino,
                    controller::error_policy,
                    Arc::new(controller::Ctx {
                        client: client.clone(),
                        product_config,
                    }),
                )
                .map(|res| {
                    report_controller_reconciled(
                        &client,
                        &format!("{CONTROLLER_NAME}.{OPERATOR_NAME}"),
                        &res,
                    )
                })
                .collect::<()>()
                .await;
        }
    }

    Ok(())
}

fn references_authentication_class(
    trino: &TrinoCluster,
    authentication_class: &AuthenticationClass,
) -> bool {
    let authentication_class_name = authentication_class.name_any();
    trino
        .spec
        .cluster_config
        .authentication
        .iter()
        .any(|a| a.authentication_class == authentication_class_name)
}
