//! See docs/modules/trino/pages/operations/graceful-shutdown.adoc for details
//! on how the implementation works
use std::collections::BTreeMap;

use indoc::formatdoc;
use snafu::{ResultExt, Snafu};
use stackable_operator::{
    builder::pod::{PodBuilder, container::ContainerBuilder},
    k8s_openapi::api::core::v1::{ExecAction, LifecycleHandler},
    shared::time::Duration,
};

use crate::{
    controller::{ValidatedCluster, ValidatedTrinoConfig},
    crd::{DEFAULT_WORKER_GRACEFUL_SHUTDOWN_TIMEOUT, TrinoRole},
};

/// Corresponds to "shutdown.grace-period", which defaults to 2 min.
/// This seems a bit high, as Pod termination - even with no queries running on the worker -
/// takes at least 4 minutes (see <https://trino.io/docs/current/admin/graceful-shutdown.html>).
/// So we set it to 30 seconds, so the Pod termination takes at least 1 minute.
const WORKER_SHUTDOWN_GRACE_PERIOD: Duration = Duration::from_secs(30);

/// Safety puffer to guarantee the graceful shutdown works every time.
const WORKER_GRACEFUL_SHUTDOWN_SAFETY_OVERHEAD: Duration = Duration::from_secs(10);

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("failed to set terminationGracePeriod"))]
    SetTerminationGracePeriod {
        source: stackable_operator::builder::pod::Error,
    },
}

/// Computes the graceful-shutdown-related properties for the role's
/// `config.properties` file from a [`ValidatedCluster`].
pub fn graceful_shutdown_config_properties(
    cluster: &ValidatedCluster,
    role: TrinoRole,
) -> BTreeMap<String, String> {
    match role {
        TrinoRole::Coordinator => {
            // Only set query.max-execution-time if fault tolerant execution is not configured.
            // With fault tolerant execution enabled, queries can be retried and run indefinitely.
            if cluster.cluster_config.fault_tolerant_execution.is_none() {
                let min_worker_graceful_shutdown_timeout =
                    min_worker_graceful_shutdown_timeout(cluster);
                // We know that queries taking longer than the minimum gracefulShutdownTimeout are subject to failure.
                // Read operator docs for reasoning.
                BTreeMap::from([(
                    "query.max-execution-time".to_string(),
                    format!("{}s", min_worker_graceful_shutdown_timeout.as_secs()),
                )])
            } else {
                BTreeMap::new()
            }
        }
        TrinoRole::Worker => BTreeMap::from([(
            "shutdown.grace-period".to_string(),
            format!("{}s", WORKER_SHUTDOWN_GRACE_PERIOD.as_secs()),
        )]),
    }
}

/// Returns the minimal `gracefulShutdownTimeout` across all worker role-groups, read from the
/// validated [`ValidatedCluster::role_group_configs`].
fn min_worker_graceful_shutdown_timeout(
    cluster: &ValidatedCluster,
) -> stackable_operator::shared::time::Duration {
    cluster
        .role_group_configs
        .get(&TrinoRole::Worker)
        .into_iter()
        .flat_map(|groups| groups.values())
        .filter_map(|rg| rg.config.graceful_shutdown_timeout)
        .min()
        .unwrap_or(DEFAULT_WORKER_GRACEFUL_SHUTDOWN_TIMEOUT)
}

pub fn add_graceful_shutdown_config(
    cluster: &ValidatedCluster,
    role: &TrinoRole,
    merged_config: &ValidatedTrinoConfig,
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
                            // graceful shutdown is complete. As the Pod gets a normal SIGTERM sent once the hook
                            // exited, we need to block this call for at least the same time terminationGracePeriodSeconds
                            // does, so that we don't kill the Pod before the terminationGracePeriodSeconds is reached.

                            // FIXME: Once we have fully fledged OPA support we need to make sure that the user we choose here (e.g. admin)
                            // has the permissions to trigger a graceful shutdown by e.g. inserting the needed OPA rules transparently.
                            formatdoc!("
                                curl -v --fail --insecure -X PUT -d '\"SHUTTING_DOWN\"' -H 'Content-type: application/json' -H 'X-Trino-User: graceful-shutdown-user' -H 'X-Trino-Source: Stackable data platform' {protocol}://{host}:{port}/v1/info/state >> /proc/1/fd/1 2>&1
                                echo 'Successfully sent graceful shutdown command' >> /proc/1/fd/1 2>&1
                                echo 'Sleeping {termination_grace_period_seconds} seconds' >> /proc/1/fd/1 2>&1
                                sleep {termination_grace_period_seconds}",
                                protocol = super::ports::exposed_protocol(cluster),
                                host = "127.0.0.1",
                                port = super::ports::exposed_port(cluster),
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

#[cfg(test)]
mod tests {
    use stackable_operator::shared::time::Duration;

    use super::*;
    use crate::{
        config::fault_tolerant_execution::ResolvedFaultTolerantExecutionConfig,
        controller::build::properties::test_support::{
            MINIMAL_TRINO_YAML, empty_derefs, validated_cluster_from_yaml,
            validated_cluster_from_yaml_with_derefs,
        },
    };

    /// A worker role group without an explicit `gracefulShutdownTimeout` falls back to the
    /// product default.
    #[test]
    fn min_worker_timeout_defaults() {
        let cluster = validated_cluster_from_yaml(
            r#"
            apiVersion: trino.stackable.tech/v1alpha1
            kind: TrinoCluster
            metadata:
              name: simple-trino
              namespace: default
              uid: "e6ac237d-a6d4-43a1-8135-f36506110912"
            spec:
              image:
                productVersion: "481"
              clusterConfig:
                catalogLabelSelector: {}
              coordinators:
                roleGroups:
                  default:
                    replicas: 1
              workers:
                roleGroups:
                  default:
                    replicas: 1
            "#,
        );
        assert_eq!(
            min_worker_graceful_shutdown_timeout(&cluster),
            DEFAULT_WORKER_GRACEFUL_SHUTDOWN_TIMEOUT
        );
    }

    /// A role-level `gracefulShutdownTimeout` is merged into every worker role group.
    #[test]
    fn min_worker_timeout_from_role() {
        let cluster = validated_cluster_from_yaml(
            r#"
            apiVersion: trino.stackable.tech/v1alpha1
            kind: TrinoCluster
            metadata:
              name: simple-trino
              namespace: default
              uid: "e6ac237d-a6d4-43a1-8135-f36506110912"
            spec:
              image:
                productVersion: "481"
              clusterConfig:
                catalogLabelSelector: {}
              coordinators:
                roleGroups:
                  default:
                    replicas: 1
              workers:
                config:
                  gracefulShutdownTimeout: 42h
                roleGroups:
                  default:
                    replicas: 1
            "#,
        );
        assert_eq!(
            min_worker_graceful_shutdown_timeout(&cluster),
            Duration::from_hours_unchecked(42)
        );
    }

    /// The minimum is taken across all worker role groups (role <- role-group merge applied).
    #[test]
    fn min_worker_timeout_across_role_groups() {
        let cluster = validated_cluster_from_yaml(
            r#"
            apiVersion: trino.stackable.tech/v1alpha1
            kind: TrinoCluster
            metadata:
              name: simple-trino
              namespace: default
              uid: "e6ac237d-a6d4-43a1-8135-f36506110912"
            spec:
              image:
                productVersion: "481"
              clusterConfig:
                catalogLabelSelector: {}
              coordinators:
                roleGroups:
                  default:
                    replicas: 1
              workers:
                config:
                  gracefulShutdownTimeout: 42h
                roleGroups:
                  normal:
                    replicas: 1
                  short:
                    replicas: 1
                    config:
                      gracefulShutdownTimeout: 5m
                  long:
                    replicas: 1
                    config:
                      gracefulShutdownTimeout: 7d
            "#,
        );
        assert_eq!(
            min_worker_graceful_shutdown_timeout(&cluster),
            Duration::from_minutes_unchecked(5)
        );
    }

    fn fte_derefs() -> crate::controller::dereference::DereferencedObjects {
        let mut derefs = empty_derefs();
        derefs.resolved_fte_config = Some(ResolvedFaultTolerantExecutionConfig {
            config_properties: BTreeMap::new(),
            exchange_manager_properties: BTreeMap::new(),
            volumes: Vec::new(),
            volume_mounts: Vec::new(),
            init_container_extra_start_commands: Vec::new(),
        });
        derefs
    }

    #[test]
    fn coordinator_props_set_query_max_execution_time_without_fte() {
        let cluster = validated_cluster_from_yaml(MINIMAL_TRINO_YAML);
        let props = graceful_shutdown_config_properties(&cluster, TrinoRole::Coordinator);
        // The default worker graceful-shutdown timeout is 60 minutes (3600s).
        assert_eq!(
            props.get("query.max-execution-time").map(String::as_str),
            Some("3600s")
        );
    }

    #[test]
    fn coordinator_props_empty_with_fault_tolerant_execution() {
        let cluster = validated_cluster_from_yaml_with_derefs(MINIMAL_TRINO_YAML, fte_derefs());
        let props = graceful_shutdown_config_properties(&cluster, TrinoRole::Coordinator);
        // With fault-tolerant execution, queries may be retried, so no max-execution-time is set.
        assert!(props.is_empty());
    }

    #[test]
    fn worker_props_set_shutdown_grace_period() {
        let cluster = validated_cluster_from_yaml(MINIMAL_TRINO_YAML);
        let props = graceful_shutdown_config_properties(&cluster, TrinoRole::Worker);
        assert_eq!(
            props.get("shutdown.grace-period").map(String::as_str),
            Some("30s")
        );
    }

    #[test]
    fn worker_termination_grace_period_adds_overhead_and_sets_pre_stop() {
        let cluster = validated_cluster_from_yaml(MINIMAL_TRINO_YAML);
        let merged = &cluster.role_group_configs[&TrinoRole::Worker]
            .values()
            .next()
            .unwrap()
            .config;
        let mut pod_builder = PodBuilder::new();
        let mut trino_builder = ContainerBuilder::new("trino").unwrap();
        add_graceful_shutdown_config(
            &cluster,
            &TrinoRole::Worker,
            merged,
            &mut pod_builder,
            &mut trino_builder,
        )
        .unwrap();

        // Default worker timeout 3600s + 2 * 30s grace + 10s safety = 3670s.
        let spec = pod_builder.build_template().spec.unwrap();
        assert_eq!(spec.termination_grace_period_seconds, Some(3670));

        let command = trino_builder
            .build()
            .lifecycle
            .unwrap()
            .pre_stop
            .unwrap()
            .exec
            .unwrap()
            .command
            .unwrap();
        assert!(command.iter().any(|arg| arg.contains("sleep 3670")));
    }

    #[test]
    fn coordinator_termination_grace_period_has_no_overhead_or_pre_stop() {
        let cluster = validated_cluster_from_yaml(MINIMAL_TRINO_YAML);
        let merged = &cluster.role_group_configs[&TrinoRole::Coordinator]
            .values()
            .next()
            .unwrap()
            .config;
        let mut pod_builder = PodBuilder::new();
        let mut trino_builder = ContainerBuilder::new("trino").unwrap();
        add_graceful_shutdown_config(
            &cluster,
            &TrinoRole::Coordinator,
            merged,
            &mut pod_builder,
            &mut trino_builder,
        )
        .unwrap();

        // The coordinator default timeout (900s) is used verbatim, with no overhead.
        let spec = pod_builder.build_template().spec.unwrap();
        assert_eq!(spec.termination_grace_period_seconds, Some(900));
        // Coordinators do not get a graceful-shutdown pre-stop hook.
        assert!(trino_builder.build().lifecycle.is_none());
    }
}
