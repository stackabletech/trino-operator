//! See docs/modules/trino/pages/operations/graceful-shutdown.adoc for details
//! on how the implementation works
use std::collections::BTreeMap;

use indoc::formatdoc;
use stackable_operator::{
    builder::{ContainerBuilder, PodBuilder},
    k8s_openapi::api::core::v1::{ExecAction, LifecycleHandler},
};
use stackable_trino_crd::{
    TrinoCluster, TrinoRole, GRACEFUL_SHUTDOWN_GRACE_PERIOD_SECONDS,
    GRACEFUL_SHUTDOWN_SAFETY_OVERHEAD_SECONDS,
};

pub fn graceful_shutdown_config_properties(
    trino: &TrinoCluster,
    role: &TrinoRole,
) -> BTreeMap<String, Option<String>> {
    let graceful_shutdown_seconds = trino.spec.cluster_config.graceful_shutdown_seconds;

    match role {
        TrinoRole::Coordinator => BTreeMap::from([(
            "query.max-execution-time".to_string(),
            Some(format!("{graceful_shutdown_seconds}s")),
        )]),
        TrinoRole::Worker => BTreeMap::from([(
            "shutdown.grace-period".to_string(),
            Some(format!("{GRACEFUL_SHUTDOWN_GRACE_PERIOD_SECONDS}s")),
        )]),
    }
}

pub fn add_graceful_shutdown_config(
    trino: &TrinoCluster,
    role: &TrinoRole,
    pod_builder: &mut PodBuilder,
    trino_builder: &mut ContainerBuilder,
) {
    // Graceful shutdown only affects workers.
    // When a coordinators get's shut down - as of Trino 423 - all queries will die anyway :/
    if role != &TrinoRole::Worker {
        return;
    }

    let graceful_shutdown_seconds = trino.spec.cluster_config.graceful_shutdown_seconds;
    let termination_grace_period_seconds = graceful_shutdown_seconds
        + 2 * GRACEFUL_SHUTDOWN_GRACE_PERIOD_SECONDS
        + GRACEFUL_SHUTDOWN_SAFETY_OVERHEAD_SECONDS;

    pod_builder.termination_grace_period_seconds(termination_grace_period_seconds as i64);
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
