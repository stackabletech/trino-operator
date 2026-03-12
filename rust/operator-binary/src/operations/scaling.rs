//! Trino scaling hooks — gracefully shuts down workers before scale-down.
//!
//! On scale-down, the `pre_scale` hook sends `PUT /v1/info/state` with
//! `"SHUTTING_DOWN"` to each worker being removed, then polls until all
//! report `INACTIVE`. The StatefulSet replica count is only reduced after
//! the hook returns `Done`, guaranteeing running queries complete.
//!
//! See <https://trino.io/docs/current/admin/graceful-shutdown.html>.

use snafu::{ResultExt, Snafu};
use stackable_operator::crd::scaler::{HookOutcome, ScalingContext, ScalingHooks};
use tracing::info;

use super::trino_api::{self, TrinoWorkerClient, TrinoWorkerState};

/// Errors from Trino scaling hook operations.
#[derive(Debug, Snafu)]
pub enum Error {
    /// Failed to create the HTTP client for a worker.
    #[snafu(display("failed to create Trino API client for worker at {base_url}"))]
    CreateClient {
        source: trino_api::Error,
        base_url: String,
    },

    /// Failed to query the worker state.
    #[snafu(display("failed to get state of worker at {base_url}"))]
    GetWorkerState {
        source: trino_api::Error,
        base_url: String,
    },

    /// Failed to initiate graceful shutdown on a worker.
    #[snafu(display("failed to initiate shutdown of worker at {base_url}"))]
    InitiateShutdown {
        source: trino_api::Error,
        base_url: String,
    },
}

/// Implements pre/post-scale hooks for Trino clusters.
///
/// On scale-down, `pre_scale` drives the Trino REST API to gracefully shut down
/// the highest-ordinal workers before the StatefulSet replica count is reduced.
pub struct TrinoScalingHooks {
    /// Name of the StatefulSet for the worker role group (e.g., `"trino-worker-default"`).
    pub statefulset_name: String,
    /// Name of the headless service for the role group.
    pub headless_service_name: String,
    /// Namespace of the cluster.
    pub namespace: String,
    /// Kubernetes cluster domain (e.g., `"cluster.local"`).
    pub cluster_domain: String,
    /// Protocol to use for the Trino REST API (`"http"` or `"https"`).
    pub exposed_protocol: String,
    /// Port of the Trino REST API (e.g., `8443` for HTTPS).
    pub exposed_port: u16,
}

impl TrinoScalingHooks {
    /// Build the FQDN for a Trino worker pod by ordinal.
    ///
    /// Format: `{sts_name}-{ordinal}.{headless_svc}.{namespace}.svc.{cluster_domain}`
    fn pod_fqdn(&self, ordinal: i32) -> String {
        format!(
            "{sts_name}-{ordinal}.{headless_svc}.{namespace}.svc.{cluster_domain}",
            sts_name = self.statefulset_name,
            headless_svc = self.headless_service_name,
            namespace = self.namespace,
            cluster_domain = self.cluster_domain,
        )
    }

    /// Build the Trino REST API base URL for a given worker ordinal.
    fn worker_base_url(&self, ordinal: i32) -> String {
        format!(
            "{protocol}://{fqdn}:{port}",
            protocol = self.exposed_protocol,
            fqdn = self.pod_fqdn(ordinal),
            port = self.exposed_port,
        )
    }

    /// Drive graceful shutdown for all workers being removed.
    ///
    /// For each removed ordinal:
    /// - `ACTIVE` → send `SHUTTING_DOWN`, mark in-progress
    /// - `SHUTTING_DOWN` → still draining, mark in-progress
    /// - `INACTIVE` → fully drained, ready for termination
    ///
    /// Returns `Done` when all targets are `INACTIVE`.
    async fn drive_scale_down(&self, ctx: &ScalingContext<'_>) -> Result<HookOutcome, Error> {
        let mut any_in_progress = false;

        for ordinal in ctx.removed_ordinals() {
            let base_url = self.worker_base_url(ordinal);
            let client = TrinoWorkerClient::new(&base_url).context(CreateClientSnafu {
                base_url: &base_url,
            })?;

            let state = client.get_state().await.context(GetWorkerStateSnafu {
                base_url: &base_url,
            })?;

            match state {
                TrinoWorkerState::Active => {
                    info!(
                        ordinal,
                        base_url = %base_url,
                        "Initiating graceful shutdown on active Trino worker"
                    );
                    client
                        .initiate_shutdown()
                        .await
                        .context(InitiateShutdownSnafu {
                            base_url: &base_url,
                        })?;
                    any_in_progress = true;
                }
                TrinoWorkerState::ShuttingDown => {
                    info!(
                        ordinal,
                        base_url = %base_url,
                        "Trino worker still shutting down, waiting"
                    );
                    any_in_progress = true;
                }
                TrinoWorkerState::Inactive => {
                    info!(
                        ordinal,
                        base_url = %base_url,
                        "Trino worker is inactive, ready for termination"
                    );
                }
            }
        }

        if any_in_progress {
            Ok(HookOutcome::InProgress)
        } else {
            Ok(HookOutcome::Done)
        }
    }
}

impl ScalingHooks for TrinoScalingHooks {
    type Error = Error;

    async fn pre_scale(&self, ctx: &ScalingContext<'_>) -> Result<HookOutcome, Error> {
        if !ctx.is_scale_down() {
            return Ok(HookOutcome::Done);
        }
        self.drive_scale_down(ctx).await
    }

    // post_scale: use trait default (returns Done immediately).
    // on_failure: use trait default (no-op).
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hooks() -> TrinoScalingHooks {
        TrinoScalingHooks {
            statefulset_name: "trino-worker-default".to_string(),
            headless_service_name: "trino-worker-default".to_string(),
            namespace: "default".to_string(),
            cluster_domain: "cluster.local".to_string(),
            exposed_protocol: "https".to_string(),
            exposed_port: 8443,
        }
    }

    #[test]
    fn pod_fqdn_is_correct() {
        let h = hooks();
        assert_eq!(
            h.pod_fqdn(2),
            "trino-worker-default-2.trino-worker-default.default.svc.cluster.local"
        );
    }

    #[test]
    fn worker_base_url_is_correct() {
        let h = hooks();
        assert_eq!(
            h.worker_base_url(0),
            "https://trino-worker-default-0.trino-worker-default.default.svc.cluster.local:8443"
        );
    }
}
