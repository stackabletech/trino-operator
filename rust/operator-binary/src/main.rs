mod authentication;
mod authorization;
mod catalog;
mod command;
mod config;
mod controller;
mod crd;
mod operations;
mod product_logging;

use std::{ops::Deref as _, sync::Arc};

use clap::Parser;
use futures::stream::StreamExt;
use stackable_operator::{
    YamlSchema,
    cli::{Command, ProductOperatorRun, RollingPeriod},
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
use stackable_telemetry::{Tracing, tracing::settings::Settings};
use tracing::level_filters::LevelFilter;

use crate::{
    controller::{FULL_CONTROLLER_NAME, OPERATOR_NAME},
    crd::{TrinoCluster, catalog::TrinoCatalog, v1alpha1},
};

mod built_info {
    include!(concat!(env!("OUT_DIR"), "/built.rs"));
}

// TODO (@NickLarsenNZ): Change the variable to `CONSOLE_LOG`
pub const ENV_VAR_CONSOLE_LOG: &str = "TRINO_OPERATOR_LOG";

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
            telemetry_arguments,
            cluster_info_opts,
        }) => {
            let _tracing_guard = Tracing::builder()
                .service_name("trino-operator")
                .with_console_output((
                    ENV_VAR_CONSOLE_LOG,
                    LevelFilter::INFO,
                    !telemetry_arguments.no_console_output,
                ))
                // NOTE (@NickLarsenNZ): Before stackable-telemetry was used, the log directory was
                // set via an env: `TRINO_OPERATOR_LOG_DIRECTORY`.
                // See: https://github.com/stackabletech/operator-rs/blob/f035997fca85a54238c8de895389cc50b4d421e2/crates/stackable-operator/src/logging/mod.rs#L40
                // Now it will be `ROLLING_LOGS` (or via `--rolling-logs <DIRECTORY>`).
                .with_file_output(telemetry_arguments.rolling_logs.map(|log_directory| {
                    let rotation_period = telemetry_arguments
                        .rolling_logs_period
                        .unwrap_or(RollingPeriod::Never)
                        .deref()
                        .clone();

                    Settings::builder()
                        .with_environment_variable(ENV_VAR_CONSOLE_LOG)
                        .with_default_level(LevelFilter::INFO)
                        .file_log_settings_builder(log_directory, "tracing-rs.json")
                        .with_rotation_period(rotation_period)
                        .build()
                }))
                .with_otlp_log_exporter((
                    "OTLP_LOG",
                    LevelFilter::DEBUG,
                    telemetry_arguments.otlp_logs,
                ))
                .with_otlp_trace_exporter((
                    "OTLP_TRACE",
                    LevelFilter::DEBUG,
                    telemetry_arguments.otlp_traces,
                ))
                .build()
                .init()?;

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
