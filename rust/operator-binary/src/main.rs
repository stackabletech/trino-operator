// TODO: Look into how to properly resolve `clippy::result_large_err`.
// This will need changes in our and upstream error types.
#![allow(clippy::result_large_err)]
mod authentication;
mod authorization;
mod catalog;
mod command;
mod config;
mod controller;
mod crd;
mod listener;
mod operations;
mod product_logging;
mod service;

use std::sync::Arc;

use clap::Parser;
use futures::stream::StreamExt;
use stackable_operator::{
    YamlSchema,
    cli::{Command, RunArguments},
    crd::authentication::core,
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
    telemetry::Tracing,
};

use crate::{
    controller::{FULL_CONTROLLER_NAME, OPERATOR_NAME},
    crd::{
        TrinoCluster, TrinoClusterVersion,
        catalog::{TrinoCatalog, TrinoCatalogVersion},
        v1alpha1,
    },
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
            TrinoCluster::merged_crd(TrinoClusterVersion::V1Alpha1)?
                .print_yaml_schema(built_info::PKG_VERSION, SerializeOptions::default())?;
            TrinoCatalog::merged_crd(TrinoCatalogVersion::V1Alpha1)?
                .print_yaml_schema(built_info::PKG_VERSION, SerializeOptions::default())?;
        }
        Command::Run(RunArguments {
            operator_environment: _,
            watch_namespace,
            product_config,
            maintenance: _,
            common,
        }) => {
            // NOTE (@NickLarsenNZ): Before stackable-telemetry was used:
            // - The console log level was set by `TRINO_OPERATOR_LOG`, and is now `CONSOLE_LOG` (when using Tracing::pre_configured).
            // - The file log level was set by `TRINO_OPERATOR_LOG`, and is now set via `FILE_LOG` (when using Tracing::pre_configured).
            // - The file log directory was set by `TRINO_OPERATOR_LOG_DIRECTORY`, and is now set by `ROLLING_LOGS_DIR` (or via `--rolling-logs <DIRECTORY>`).
            let _tracing_guard =
                Tracing::pre_configured(built_info::PKG_NAME, common.telemetry).init()?;

            tracing::info!(
                built_info.pkg_version = built_info::PKG_VERSION,
                built_info.git_version = built_info::GIT_VERSION,
                built_info.target = built_info::TARGET,
                built_info.built_time_utc = built_info::BUILT_TIME_UTC,
                built_info.rustc_version = built_info::RUSTC_VERSION,
                "Starting {description}",
                description = built_info::PKG_DESCRIPTION
            );
            let product_config = product_config.load(&[
                "deploy/config-spec/properties.yaml",
                "/etc/stackable/trino-operator/config-spec/properties.yaml",
            ])?;

            let client = stackable_operator::client::initialize_operator(
                Some(OPERATOR_NAME.to_string()),
                &common.cluster_info,
            )
            .await?;
            let event_recorder = Arc::new(Recorder::new(
                client.as_kube_client(),
                Reporter {
                    controller: FULL_CONTROLLER_NAME.to_string(),
                    instance: None,
                },
            ));

            let cluster_controller = Controller::new(
                watch_namespace.get_api::<DeserializeGuard<v1alpha1::TrinoCluster>>(&client),
                watcher::Config::default(),
            );
            let catalog_cluster_store = cluster_controller.store();
            let authentication_class_cluster_store = cluster_controller.store();
            let config_map_cluster_store = cluster_controller.store();

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
                    client.get_api::<DeserializeGuard<core::v1alpha1::AuthenticationClass>>(&()),
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
                .watches(
                    watch_namespace.get_api::<DeserializeGuard<ConfigMap>>(&client),
                    watcher::Config::default(),
                    move |config_map| {
                        config_map_cluster_store
                            .state()
                            .into_iter()
                            .filter(move |druid| references_config_map(druid, &config_map))
                            .map(|druid| ObjectRef::from_obj(&*druid))
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
    authentication_class: &DeserializeGuard<core::v1alpha1::AuthenticationClass>,
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

fn references_config_map(
    trino: &DeserializeGuard<v1alpha1::TrinoCluster>,
    config_map: &DeserializeGuard<ConfigMap>,
) -> bool {
    let Ok(trino) = &trino.0 else {
        return false;
    };

    match &trino.spec.cluster_config.authorization {
        Some(trino_authorization) => match &trino_authorization.opa {
            Some(opa_config) => opa_config.config_map_name == config_map.name_any(),
            None => false,
        },
        None => false,
    }
}
