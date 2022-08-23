mod catalog;
mod command;
mod controller;

use clap::Parser;
use futures::stream::StreamExt;
use stackable_operator::{
    cli::{Command, ProductOperatorRun},
    k8s_openapi::api::{
        apps::v1::StatefulSet,
        core::v1::{ConfigMap, Service},
    },
    kube::{
        api::ListParams,
        runtime::{reflector::ObjectRef, Controller},
        CustomResourceExt, ResourceExt,
    },
    logging::controller::report_controller_reconciled,
};
use stackable_trino_crd::{catalog::TrinoCatalog, TrinoCluster, APP_NAME};
use std::sync::Arc;

mod built_info {
    include!(concat!(env!("OUT_DIR"), "/built.rs"));
}

#[derive(Parser)]
#[clap(about = built_info::PKG_DESCRIPTION, author = stackable_operator::cli::AUTHOR)]
struct Opts {
    #[clap(subcommand)]
    cmd: Command,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opts = Opts::parse();
    match opts.cmd {
        // TODO: Replace with new yaml serde mechanism from operator-rs
        Command::Crd => println!(
            "{}---\n{}",
            serde_yaml::to_string(&TrinoCluster::crd())?,
            serde_yaml::to_string(&TrinoCatalog::crd())?
        ),
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
                built_info::PKG_DESCRIPTION,
                built_info::PKG_VERSION,
                built_info::GIT_VERSION,
                built_info::TARGET,
                built_info::BUILT_TIME_UTC,
                built_info::RUSTC_VERSION,
            );
            let product_config = product_config.load(&[
                "deploy/config-spec/properties.yaml",
                "/etc/stackable/trino-operator/config-spec/properties.yaml",
            ])?;

            let client =
                stackable_operator::client::create_client(Some("trino.stackable.tech".to_string()))
                    .await?;

            let cluster_controller = Controller::new(
                watch_namespace.get_api::<TrinoCluster>(&client),
                ListParams::default(),
            );
            let cluster_store = cluster_controller.store();
            cluster_controller
                .owns(
                    watch_namespace.get_api::<Service>(&client),
                    ListParams::default(),
                )
                .owns(
                    watch_namespace.get_api::<StatefulSet>(&client),
                    ListParams::default(),
                )
                .owns(
                    watch_namespace.get_api::<ConfigMap>(&client),
                    ListParams::default(),
                )
                .watches(
                    watch_namespace.get_api::<TrinoCatalog>(&client),
                    ListParams::default(),
                    move |catalog| {
                        // TODO: Filter clusters more precisely based on the catalogLabelSelector to avoid unnecessary reconciles
                        cluster_store
                            .state()
                            .into_iter()
                            // Catalogs can only be referenced within namespaces
                            .filter(move |cluster| cluster.namespace() == catalog.namespace())
                            .map(|cluster| ObjectRef::from_obj(&*cluster))
                    },
                )
                .shutdown_on_signal()
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
                        "trinoclusters.trino.stackable.tech",
                        &res,
                    )
                })
                .collect::<()>()
                .await;
        }
    }

    Ok(())
}
