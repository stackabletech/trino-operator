mod authentication;
mod authorization;
mod catalog;
mod command;
mod config;
mod controller;
mod crd;
mod operations;
mod product_logging;

use std::sync::Arc;

use clap::{Parser, crate_description, crate_version};
use futures::stream::StreamExt;
use stackable_operator::{
    YamlSchema,
    cli::{Command, ProductOperatorRun},
    commons::authentication::AuthenticationClass,
    k8s_openapi::api::{
        apps::v1::StatefulSet,
        core::v1::{ConfigMap, Service},
    },
    kube::{
        ResourceExt,
        core::DeserializeGuard,
        runtime::{
            Controller,
            events::{Recorder, Reporter},
            reflector::ObjectRef,
            watcher,
        },
    },
    logging::controller::report_controller_reconciled,
    shared::yaml::SerializeOptions,
};

use crate::{
    controller::{FULL_CONTROLLER_NAME, OPERATOR_NAME},
    crd::{APP_NAME, TrinoCluster, catalog::TrinoCatalog, v1alpha1},
};

mod built_info {
    include!(concat!(env!("OUT_DIR"), "/built.rs"));
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
            TrinoCluster::merged_crd(TrinoCluster::V1Alpha1)?
                .print_yaml_schema(built_info::PKG_VERSION, SerializeOptions::default())?;
            TrinoCatalog::merged_crd(TrinoCatalog::V1Alpha1)?
                .print_yaml_schema(built_info::PKG_VERSION, SerializeOptions::default())?;
        }
        Command::Run(ProductOperatorRun {
            product_config,
            watch_namespace,
            tracing_target,
            cluster_info_opts,
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
                built_info::TARGET,
                built_info::BUILT_TIME_UTC,
                built_info::RUSTC_VERSION,
            );
            let product_config = product_config.load(&[
                "deploy/config-spec/properties.yaml",
                "/etc/stackable/trino-operator/config-spec/properties.yaml",
            ])?;

            let client = stackable_operator::client::initialize_operator(
                Some(OPERATOR_NAME.to_string()),
                &cluster_info_opts,
            )
            .await?;
            let event_recorder = Arc::new(Recorder::new(client.as_kube_client(), Reporter {
                controller: FULL_CONTROLLER_NAME.to_string(),
                instance: None,
            }));

            let cluster_controller = Controller::new(
                watch_namespace.get_api::<DeserializeGuard<v1alpha1::TrinoCluster>>(&client),
                watcher::Config::default(),
            );
            let catalog_cluster_store = Arc::new(cluster_controller.store());
            let authentication_class_cluster_store = catalog_cluster_store.clone();

            cluster_controller
                .owns(
                    watch_namespace.get_api::<DeserializeGuard<Service>>(&client),
                    watcher::Config::default(),
                )
                .owns(
                    watch_namespace.get_api::<DeserializeGuard<StatefulSet>>(&client),
                    watcher::Config::default(),
                )
                .owns(
                    watch_namespace.get_api::<DeserializeGuard<ConfigMap>>(&client),
                    watcher::Config::default(),
                )
                .shutdown_on_signal()
                .watches(
                    watch_namespace
                        .get_api::<DeserializeGuard<crd::catalog::v1alpha1::TrinoCatalog>>(&client),
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
                    client.get_api::<DeserializeGuard<AuthenticationClass>>(&()),
                    watcher::Config::default(),
                    move |authentication_class| {
                        authentication_class_cluster_store
                            .state()
                            .into_iter()
                            .filter(move |trino| {
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
                // We can let the reporting happen in the background
                .for_each_concurrent(
                    16, // concurrency limit
                    |result| {
                        // The event_recorder needs to be shared across all invocations, so that
                        // events are correctly aggregated
                        let event_recorder = event_recorder.clone();
                        async move {
                            report_controller_reconciled(
                                &event_recorder,
                                FULL_CONTROLLER_NAME,
                                &result,
                            )
                            .await;
                        }
                    },
                )
                .await;
        }
    }

    Ok(())
}

fn references_authentication_class(
    trino: &DeserializeGuard<v1alpha1::TrinoCluster>,
    authentication_class: &DeserializeGuard<AuthenticationClass>,
) -> bool {
    let Ok(trino) = &trino.0 else {
        return false;
    };

    let authentication_class_name = authentication_class.name_any();
    trino
        .spec
        .cluster_config
        .authentication
        .iter()
        .any(|c| c.authentication_class_name() == &authentication_class_name)
}
