//! See docs/modules/trino/pages/operations/graceful-shutdown.adoc for details
//! on how the implementation works
use std::collections::BTreeMap;

use indoc::formatdoc;
use snafu::{ResultExt, Snafu};
use stackable_operator::{
    builder::{ContainerBuilder, PodBuilder},
    k8s_openapi::api::core::v1::{ExecAction, LifecycleHandler},
};
use stackable_trino_crd::{
    TrinoCluster, TrinoConfig, TrinoRole, WORKER_GRACEFUL_SHUTDOWN_SAFETY_OVERHEAD,
    WORKER_SHUTDOWN_GRACE_PERIOD,
};

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Failed to set terminationGracePeriod"))]
    SetTerminationGracePeriod {
        source: stackable_operator::builder::pod::Error,
    },
}

pub fn graceful_shutdown_config_properties(
    trino: &TrinoCluster,
    role: &TrinoRole,
) -> BTreeMap<String, Option<String>> {
    match role {
        TrinoRole::Coordinator => {
            let min_graceful_shutdown_timeout = trino.min_worker_graceful_shutdown_timeout();
            // We know that queries taking longer than the minimum gracefulShutdownTimeout are subject to failure.
            // Read operator docs for reasoning.
            BTreeMap::from([(
                "query.max-execution-time".to_string(),
                Some(format!("{}s", min_graceful_shutdown_timeout.as_secs())),
            )])
        }
        TrinoRole::Worker => BTreeMap::from([(
            "shutdown.grace-period".to_string(),
            Some(format!("{}s", WORKER_SHUTDOWN_GRACE_PERIOD.as_secs())),
        )]),
    }
}

pub fn add_graceful_shutdown_config(
    trino: &TrinoCluster,
    role: &TrinoRole,
    merged_config: &TrinoConfig,
    pod_builder: &mut PodBuilder,
    trino_builder: &mut ContainerBuilder,
) -> Result<(), Error> {
    // This must be always set by the merge mechanism, as we provide a default value,
    // users can not disable graceful shutdown.
    if let Some(graceful_shutdown_timeout) = merged_config.graceful_shutdown_timeout {
        match role {
            TrinoRole::Coordinator => {
                pod_builder
                    .termination_grace_period(&graceful_shutdown_timeout)
                    .context(SetTerminationGracePeriodSnafu)?;
            }
            TrinoRole::Worker => {
                // We could stick `graceful_shutdown_timeout` into the Pod's `termination_grace_period_seconds` and subtract all the overheads
                // from it and use that for `query.max-execution-time`. However, as `query.max-execution-time` is user-facing, we set to the configured
                // `graceful_shutdown_timeout` and add the overhead to the Pod's `termination_grace_period_seconds`.
                let termination_grace_period = graceful_shutdown_timeout
                    + 2 * WORKER_SHUTDOWN_GRACE_PERIOD
                    + WORKER_GRACEFUL_SHUTDOWN_SAFETY_OVERHEAD;
                let termination_grace_period_seconds = termination_grace_period.as_secs();

                pod_builder
                    .termination_grace_period(&termination_grace_period)
                    .context(SetTerminationGracePeriodSnafu)?;
                trino_builder.lifecycle_pre_stop(LifecycleHandler {
                    exec: Some(ExecAction {
                        command: Some(vec![
                            "/bin/bash".to_string(),
                            "-x".to_string(),
                            "-euo".to_string(),
                            "pipefail".to_string(),
                            "-c".to_string(),
                            // The curl does not block, but the worker process will terminate automatically once the
                            // graceful shutdown is complete. As the Pod gets a normal SIGINT sent once the hook
                            // exited, we need to block this call for at least the same time terminationGracePeriodSeconds
                            // does, so that we don't kill the Pod before the terminationGracePeriodSeconds is reached.

                            // FIXME: Once we have fully fledged OPA support we need to make sure that the user we choose here (e.g. admin)
                            // has the permissions to trigger a graceful shutdown by e.g. inserting the needed OPA rules transparently.
                            formatdoc!("
                                curl -v --fail --insecure -X PUT -d '\"SHUTTING_DOWN\"' -H 'Content-type: application/json' -H 'X-Trino-User: admin' {protocol}://{host}:{port}/v1/info/state >> /proc/1/fd/1 2>&1
                                echo 'Successfully sent graceful shutdown command' >> /proc/1/fd/1 2>&1
                                echo 'Sleeping {termination_grace_period_seconds} seconds' >> /proc/1/fd/1 2>&1
                                sleep {termination_grace_period_seconds}",
                                protocol = trino.exposed_protocol(),
                                host = "127.0.0.1",
                                port = trino.exposed_port(),
                            ),
                        ]),
                    }),
                    ..Default::default()
                });
            }
        }
    }

    Ok(())
}
