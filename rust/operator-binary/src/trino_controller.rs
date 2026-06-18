//! Ensures that `Pod`s are configured and running for each [`v1alpha1::TrinoCluster`]
use std::sync::Arc;

use const_format::concatcp;
use snafu::{ResultExt, Snafu};
use stackable_operator::{
    cli::OperatorEnvironmentOptions,
    cluster_resources::ClusterResourceApplyStrategy,
    commons::{random_secret_creation, rbac::build_rbac_resources},
    kube::{
        ResourceExt,
        core::{DeserializeGuard, error_boundary},
        runtime::controller::Action,
    },
    logging::controller::ReconcilerError,
    memory::{BinaryMultiple, MemoryQuantity},
    shared::time::Duration,
    status::condition::{
        compute_conditions, operations::ClusterOperationsConditionBuilder,
        statefulset::StatefulSetConditionBuilder,
    },
    v2::{cluster_resources::cluster_resources_new, types::operator::ClusterName},
};
use strum::{EnumDiscriminants, IntoStaticStr};

use crate::{
    controller::{
        RoleGroupName, build,
        build::resource::{
            listener::{build_group_listener, group_listener_name},
            pdb::build_pdb,
            service::{
                build_rolegroup_headless_service, build_rolegroup_metrics_service,
                headless_service_ports,
            },
        },
        controller_name, dereference, operator_name, product_name, validate,
    },
    crd::{APP_NAME, ENV_INTERNAL_SECRET, ENV_SPOOLING_SECRET, v1alpha1},
};

pub struct Ctx {
    pub client: stackable_operator::client::Client,
    pub operator_environment: OperatorEnvironmentOptions,
}

pub const OPERATOR_NAME: &str = "trino.stackable.tech";
pub const CONTROLLER_NAME: &str = "trinocluster";
pub const FULL_CONTROLLER_NAME: &str = concatcp!(CONTROLLER_NAME, '.', OPERATOR_NAME);

pub use stackable_operator::v2::product_logging::framework::STACKABLE_LOG_DIR;
pub const STACKABLE_LOG_CONFIG_DIR: &str = "/stackable/log_config";

pub const MAX_PREPARE_LOG_FILE_SIZE: MemoryQuantity = MemoryQuantity {
    value: 1.0,
    unit: BinaryMultiple::Mebi,
};

pub(crate) const CONTAINER_IMAGE_BASE_NAME: &str = "trino";

#[derive(Snafu, Debug, EnumDiscriminants)]
#[strum_discriminants(derive(IntoStaticStr))]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[snafu(display("failed to delete orphaned resources"))]
    DeleteOrphanedResources {
        source: stackable_operator::cluster_resources::Error,
    },

    #[snafu(display("failed to apply Service for {}", rolegroup))]
    ApplyRoleGroupService {
        source: stackable_operator::cluster_resources::Error,
        rolegroup: RoleGroupName,
    },

    #[snafu(display("failed to build ConfigMap for {}", rolegroup))]
    BuildRoleGroupConfigMap {
        source: build::resource::config_map::Error,
        rolegroup: RoleGroupName,
    },

    #[snafu(display("failed to apply ConfigMap for {}", rolegroup))]
    ApplyRoleGroupConfig {
        source: stackable_operator::cluster_resources::Error,
        rolegroup: RoleGroupName,
    },

    #[snafu(display("failed to build StatefulSet for {}", rolegroup))]
    BuildRoleGroupStatefulSet {
        source: build::resource::statefulset::Error,
        rolegroup: RoleGroupName,
    },

    #[snafu(display("failed to apply StatefulSet for {}", rolegroup))]
    ApplyRoleGroupStatefulSet {
        source: stackable_operator::cluster_resources::Error,
        rolegroup: RoleGroupName,
    },

    #[snafu(display("failed to patch service account"))]
    ApplyServiceAccount {
        source: stackable_operator::cluster_resources::Error,
    },

    #[snafu(display("failed to patch role binding"))]
    ApplyRoleBinding {
        source: stackable_operator::cluster_resources::Error,
    },

    #[snafu(display("failed to update status"))]
    ApplyStatus {
        source: stackable_operator::client::Error,
    },

    #[snafu(display("failed to build RBAC resources"))]
    BuildRbacResources {
        source: stackable_operator::commons::rbac::Error,
    },

    #[snafu(display("failed to apply PodDisruptionBudget"))]
    ApplyPdb {
        source: stackable_operator::cluster_resources::Error,
    },

    #[snafu(display("failed to get required Labels"))]
    GetRequiredLabels {
        source:
            stackable_operator::kvp::KeyValuePairError<stackable_operator::kvp::LabelValueError>,
    },

    #[snafu(display("failed to build Labels"))]
    LabelBuild {
        source: stackable_operator::kvp::LabelError,
    },

    #[snafu(display("invalid TrinoCluster object"))]
    InvalidTrinoCluster {
        source: error_boundary::InvalidObject,
    },

    #[snafu(display("failed to dereference resources"))]
    Dereference { source: dereference::Error },

    #[snafu(display("failed to validate cluster"))]
    ValidateCluster { source: validate::Error },

    #[snafu(display("failed to apply group listener"))]
    ApplyGroupListener {
        source: stackable_operator::cluster_resources::Error,
    },

    #[snafu(display("failed to create internal secret"))]
    CreateInternalSecret {
        source: random_secret_creation::Error,
    },
}

type Result<T, E = Error> = std::result::Result<T, E>;

impl ReconcilerError for Error {
    fn category(&self) -> &'static str {
        ErrorDiscriminants::from(self).into()
    }
}

pub async fn reconcile_trino(
    trino: Arc<DeserializeGuard<v1alpha1::TrinoCluster>>,
    ctx: Arc<Ctx>,
) -> Result<Action> {
    tracing::info!("Starting reconcile");

    let trino = trino
        .0
        .as_ref()
        .map_err(error_boundary::InvalidObject::clone)
        .context(InvalidTrinoClusterSnafu)?;
    let client = &ctx.client;

    // dereference (client required)
    let dereferenced_objects = dereference::dereference(client, trino)
        .await
        .context(DereferenceSnafu)?;

    // validate (no client required)
    let validated_cluster =
        validate::validate(trino, &dereferenced_objects, &ctx.operator_environment)
            .context(ValidateClusterSnafu)?;
    tracing::debug!(
        trino.name = %validated_cluster.name,
        trino.namespace = %validated_cluster.namespace,
        trino.uid = %validated_cluster.uid,
        "Validated TrinoCluster"
    );

    let mut cluster_resources = cluster_resources_new(
        &product_name(),
        &operator_name(),
        &controller_name(),
        &validated_cluster.name,
        &validated_cluster.namespace,
        &validated_cluster.uid,
        ClusterResourceApplyStrategy::from(&trino.spec.cluster_operation),
        &trino.spec.object_overrides,
    );

    let (rbac_sa, rbac_rolebinding) = build_rbac_resources(
        trino,
        APP_NAME,
        cluster_resources
            .get_required_labels()
            .context(GetRequiredLabelsSnafu)?,
    )
    .context(BuildRbacResourcesSnafu)?;

    let rbac_sa = cluster_resources
        .add(client, rbac_sa)
        .await
        .context(ApplyServiceAccountSnafu)?;

    cluster_resources
        .add(client, rbac_rolebinding)
        .await
        .context(ApplyRoleBindingSnafu)?;

    random_secret_creation::create_random_secret_if_not_exists(
        &shared_internal_secret_name(&validated_cluster.name),
        ENV_INTERNAL_SECRET,
        512,
        &validated_cluster,
        client,
    )
    .await
    .context(CreateInternalSecretSnafu)?;

    // This secret is created even if spooling is not configured.
    // Trino currently requires the secret to be exactly 256 bits long.
    random_secret_creation::create_random_secret_if_not_exists(
        &shared_spooling_secret_name(&validated_cluster.name),
        ENV_SPOOLING_SECRET,
        32,
        &validated_cluster,
        client,
    )
    .await
    .context(CreateInternalSecretSnafu)?;

    let mut sts_cond_builder = StatefulSetConditionBuilder::default();

    for (trino_role, role_group_configs) in &validated_cluster.role_group_configs {
        for (role_group_name, rg) in role_group_configs {
            let role_group_service_recommended_labels =
                validated_cluster.recommended_labels(trino_role, role_group_name);

            let role_group_service_selector =
                validated_cluster.role_group_selector(trino_role, role_group_name);

            let rg_headless_service = build_rolegroup_headless_service(
                &validated_cluster,
                trino_role,
                role_group_name,
                &role_group_service_recommended_labels,
                role_group_service_selector.clone().into(),
                headless_service_ports(&validated_cluster),
            );

            let rg_metrics_service = build_rolegroup_metrics_service(
                &validated_cluster,
                trino_role,
                role_group_name,
                &role_group_service_recommended_labels,
                role_group_service_selector.into(),
            );

            let rg_configmap = build::resource::config_map::build_rolegroup_config_map(
                &validated_cluster,
                trino_role,
                role_group_name,
                &client.kubernetes_cluster_info,
                &role_group_service_recommended_labels,
            )
            .with_context(|_| BuildRoleGroupConfigMapSnafu {
                rolegroup: role_group_name.clone(),
            })?;

            let rg_catalog_configmap =
                build::resource::config_map::build_rolegroup_catalog_config_map(
                    &validated_cluster,
                    trino_role,
                    role_group_name,
                    &role_group_service_recommended_labels,
                )
                .with_context(|_| BuildRoleGroupConfigMapSnafu {
                    rolegroup: role_group_name.clone(),
                })?;

            let rg_stateful_set = build::resource::statefulset::build_rolegroup_statefulset(
                &validated_cluster,
                trino_role,
                role_group_name,
                rg,
                &rbac_sa.name_any(),
            )
            .with_context(|_| BuildRoleGroupStatefulSetSnafu {
                rolegroup: role_group_name.clone(),
            })?;

            cluster_resources
                .add(client, rg_headless_service)
                .await
                .with_context(|_| ApplyRoleGroupServiceSnafu {
                    rolegroup: role_group_name.clone(),
                })?;

            cluster_resources
                .add(client, rg_metrics_service)
                .await
                .with_context(|_| ApplyRoleGroupServiceSnafu {
                    rolegroup: role_group_name.clone(),
                })?;

            cluster_resources
                .add(client, rg_configmap)
                .await
                .with_context(|_| ApplyRoleGroupConfigSnafu {
                    rolegroup: role_group_name.clone(),
                })?;

            cluster_resources
                .add(client, rg_catalog_configmap)
                .await
                .with_context(|_| ApplyRoleGroupConfigSnafu {
                    rolegroup: role_group_name.clone(),
                })?;

            // Note: The StatefulSet needs to be applied after all ConfigMaps and Secrets it mounts
            // to prevent unnecessary Pod restarts.
            // See https://github.com/stackabletech/commons-operator/issues/111 for details.
            sts_cond_builder.add(
                cluster_resources
                    .add(client, rg_stateful_set)
                    .await
                    .with_context(|_| ApplyRoleGroupStatefulSetSnafu {
                        rolegroup: role_group_name.clone(),
                    })?,
            );
        }

        let Some(role_config) = validated_cluster.role_config(trino_role) else {
            continue;
        };

        if let Some(listener_class) = &role_config.listener_class
            && let Some(listener_group_name) = group_listener_name(&validated_cluster, trino_role)
        {
            let role_group_listener = build_group_listener(
                &validated_cluster,
                validated_cluster
                    .recommended_labels(trino_role, &build::PLACEHOLDER_LISTENER_ROLE_GROUP),
                listener_class,
                listener_group_name,
            );

            cluster_resources
                .add(client, role_group_listener)
                .await
                .context(ApplyGroupListenerSnafu)?;
        }

        if let Some(pdb) = build_pdb(&role_config.pdb, &validated_cluster, trino_role) {
            cluster_resources
                .add(client, pdb)
                .await
                .context(ApplyPdbSnafu)?;
        }
    }

    let cluster_operation_cond_builder =
        ClusterOperationsConditionBuilder::new(&trino.spec.cluster_operation);

    let status = v1alpha1::TrinoClusterStatus {
        conditions: compute_conditions(
            trino,
            &[&sts_cond_builder, &cluster_operation_cond_builder],
        ),
    };

    cluster_resources
        .delete_orphaned_resources(client)
        .await
        .context(DeleteOrphanedResourcesSnafu)?;
    client
        .apply_patch_status(OPERATOR_NAME, trino, &status)
        .await
        .context(ApplyStatusSnafu)?;

    Ok(Action::await_change())
}

pub fn error_policy(
    _obj: Arc<DeserializeGuard<v1alpha1::TrinoCluster>>,
    error: &Error,
    _ctx: Arc<Ctx>,
) -> Action {
    match error {
        Error::InvalidTrinoCluster { .. } => Action::await_change(),
        _ => Action::requeue(*Duration::from_secs(5)),
    }
}

pub(crate) fn shared_internal_secret_name(cluster_name: &ClusterName) -> String {
    format!("{cluster_name}-internal-secret")
}

pub(crate) fn shared_spooling_secret_name(cluster_name: &ClusterName) -> String {
    format!("{cluster_name}-spooling-secret")
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use stackable_operator::{
        cli::OperatorEnvironmentOptions, commons::networking::DomainName,
        k8s_openapi::api::core::v1::ConfigMap, utils::cluster_info::KubernetesClusterInfo,
        v2::builder::pod::container::EnvVarName,
    };

    use super::*;
    use crate::{
        authorization::opa::TrinoOpaConfig,
        config::{
            client_protocol::ResolvedClientProtocolConfig,
            fault_tolerant_execution::ResolvedFaultTolerantExecutionConfig,
        },
        controller::dereference::DereferencedObjects,
        crd::{ENV_SPOOLING_SECRET, TrinoRole, v1alpha1},
    };

    async fn build_config_map(trino_yaml: &str) -> ConfigMap {
        let deserializer = serde_yaml::Deserializer::from_str(trino_yaml);
        let mut trino: v1alpha1::TrinoCluster =
            serde_yaml::with::singleton_map_recursive::deserialize(deserializer)
                .expect("invalid test input");
        trino.metadata.namespace = Some("default".to_owned());
        trino.metadata.uid = Some("e6ac237d-a6d4-43a1-8135-f36506110912".to_owned());

        let cluster_info = KubernetesClusterInfo {
            cluster_domain: DomainName::try_from("cluster.local").unwrap(),
        };

        let namespace = trino.metadata.namespace.clone().unwrap();
        let resolved_fte_config = match &trino.spec.cluster_config.fault_tolerant_execution {
            Some(fte) => Some(
                ResolvedFaultTolerantExecutionConfig::from_config(fte, None, &namespace)
                    .await
                    .unwrap(),
            ),
            None => None,
        };
        let resolved_client_protocol_config = match &trino.spec.cluster_config.client_protocol {
            Some(cp) => Some(
                ResolvedClientProtocolConfig::from_config(cp, None, &namespace)
                    .await
                    .unwrap(),
            ),
            None => None,
        };
        // Build a `TrinoOpaConfig` literal directly instead of resolving it from cluster config,
        // so that `test_access_control_overrides` does not need a Kubernetes client and
        // `test_config_overrides` still observes an `access-control.properties` entry in the
        // rendered ConfigMap.
        let trino_opa_config = Some(TrinoOpaConfig {
            non_batched_connection_string:
                "http://simple-opa.default.svc.cluster.local:8081/v1/data/my-product/allow"
                    .to_string(),
            batched_connection_string:
                "http://simple-opa.default.svc.cluster.local:8081/v1/data/my-product/batch"
                    .to_string(),
            row_filters_connection_string: Some(
                "http://simple-opa.default.svc.cluster.local:8081/v1/data/my-product/rowFilters"
                    .to_string(),
            ),
            batched_column_masking_connection_string: Some(
                "http://simple-opa.default.svc.cluster.local:8081/v1/data/my-product/batchColumnMasks"
                    .to_string(),
            ),
            allow_permission_management_operations: true,
            tls_secret_class: None,
        });

        let derefs = DereferencedObjects {
            resolved_authentication_classes: Vec::new(),
            catalog_definitions: Vec::new(),
            catalogs: Vec::new(),
            trino_opa_config,
            resolved_fte_config,
            resolved_client_protocol_config,
        };

        let operator_env = OperatorEnvironmentOptions {
            operator_namespace: "stackable-operators".to_string(),
            operator_service_name: "trino-operator".to_string(),
            image_repository: "oci.example.org".to_string(),
        };

        let validated_cluster =
            validate::validate(&trino, &derefs, &operator_env).expect("validate should succeed");

        let trino_role = TrinoRole::Coordinator;
        let role_group_name = RoleGroupName::from_str("default").expect("valid role group name");
        let recommended_labels =
            validated_cluster.recommended_labels(&trino_role, &role_group_name);

        build::resource::config_map::build_rolegroup_config_map(
            &validated_cluster,
            &trino_role,
            &role_group_name,
            &cluster_info,
            &recommended_labels,
        )
        .expect("build_rolegroup_config_map should succeed")
    }

    #[tokio::test]
    async fn test_config_overrides() {
        let trino_yaml = r#"
        apiVersion: trino.stackable.tech/v1alpha1
        kind: TrinoCluster
        metadata:
          name: simple-trino
        spec:
          image:
            productVersion: "479"
          clusterConfig:
            catalogLabelSelector:
              matchLabels:
                trino: simple-trino
          coordinators:
            configOverrides:
              config.properties:
                foo: bar
                level: role
                hello-from-role: "true"
                internal-communication.https.keystore.path: /my/custom/internal-truststore.p12
            roleGroups:
              default:
                configOverrides:
                  config.properties:
                    foo: bar
                    level: role-group
                    hello-from-role-group: "true"
                    http-server.https.truststore.path: /my/custom/truststore.p12
                replicas: 1
          workers:
            roleGroups:
              default:
                replicas: 1
        "#;
        let cm = build_config_map(trino_yaml).await.data.unwrap();
        let config = cm.get("config.properties").unwrap();
        assert!(config.contains("foo=bar"));
        assert!(config.contains("level=role-group"));
        assert!(config.contains("hello-from-role=true"));
        assert!(config.contains("hello-from-role-group=true"));
        assert!(config.contains("http-server.https.enabled=true"));
        assert!(
            config.contains("http-server.https.keystore.path=/stackable/server_tls/keystore.p12")
        );
        assert!(config.contains(
            "internal-communication.https.keystore.path=/my/custom/internal-truststore.p12"
        ));
        // Overwritten by configOverrides from role (does work)
        assert!(config.contains("http-server.https.truststore.path=/my/custom/truststore.p12"));

        assert!(cm.contains_key("jvm.config"));
        assert!(cm.contains_key("security.properties"));
        assert!(cm.contains_key("node.properties"));
        assert!(cm.contains_key("log.properties"));
        assert!(cm.contains_key("access-control.properties"));
    }

    #[tokio::test]
    async fn test_client_protocol_config_overrides() {
        let trino_yaml = r#"
        apiVersion: trino.stackable.tech/v1alpha1
        kind: TrinoCluster
        metadata:
          name: simple-trino
        spec:
          image:
            productVersion: "479"
          clusterConfig:
            catalogLabelSelector:
              matchLabels:
                trino: simple-trino
            clientProtocol:
              spooling:
                location: s3://my-bucket/spooling
                filesystem:
                  s3:
                    connection:
                      reference: test-s3-connection
          coordinators:
            configOverrides:
              config.properties:
                foo: bar
              spooling-manager.properties:
                fs.location: s3a://role-level
            roleGroups:
              default:
                replicas: 1
                configOverrides:
                  spooling-manager.properties:
                    fs.location: s3a://role-group-level
          workers:
            roleGroups:
              default:
                replicas: 1
        "#;

        let cm = build_config_map(trino_yaml).await.data.unwrap();
        let config = cm.get("config.properties").unwrap();
        assert!(config.contains("protocol.spooling.enabled=true"));
        assert!(config.contains(&format!(
            "protocol.spooling.shared-secret-key=${{ENV\\:{ENV_SPOOLING_SECRET}}}"
        )));
        assert!(config.contains("foo=bar"));

        let config = cm.get("spooling-manager.properties").unwrap();
        assert!(config.contains("fs.location=s3a\\://role-group-level"));
        assert!(config.contains("spooling-manager.name=filesystem"));
    }

    #[tokio::test]
    async fn test_access_control_overrides() {
        let trino_yaml = r#"
        apiVersion: trino.stackable.tech/v1alpha1
        kind: TrinoCluster
        metadata:
          name: trino
        spec:
          image:
            productVersion: "479"
          clusterConfig:
            catalogLabelSelector:
              matchLabels:
                trino: simple-trino
            authorization:
              opa:
                configMapName: simple-opa
                package: my-product
          coordinators:
            configOverrides:
              access-control.properties:
                hello-from-role: "true" # only defined here at role level
                foo.bar: "false" # overridden by role group below
                opa.allow-permission-management-operations: "false" # override value from config
            roleGroups:
              default:
                configOverrides:
                  access-control.properties:
                    hello-from-role-group: "true" # only defined here at group level
                    foo.bar: "true" # overrides role value
                    opa.policy.batched-uri: "http://simple-opa.default.svc.cluster.local:8081/v1/data/my-product/batch-new" # override value from config
                    opa.policy.batch-column-masking-uri: "http://simple-opa.default.svc.cluster.local:8081/v1/data/my-product/batchColumnMasks-new" # override value from config
                replicas: 1
          workers:
            roleGroups:
              default:
                replicas: 1
        "#;

        let cm = build_config_map(trino_yaml).await.data.unwrap();
        let access_control_config = cm.get("access-control.properties").unwrap();

        assert!(access_control_config.contains("access-control.name=opa"));
        assert!(access_control_config.contains("hello-from-role=true"));
        assert!(access_control_config.contains("hello-from-role-group=true"));
        assert!(access_control_config.contains("foo.bar=true"));
        assert!(access_control_config.contains("opa.allow-permission-management-operations=false"));
        assert!(access_control_config.contains(r#"opa.policy.batched-uri=http\://simple-opa.default.svc.cluster.local\:8081/v1/data/my-product/batch-new"#));
        assert!(access_control_config.contains(r#"opa.policy.batch-column-masking-uri=http\://simple-opa.default.svc.cluster.local\:8081/v1/data/my-product/batchColumnMasks-new"#));
        assert!(access_control_config.contains(r#"opa.policy.row-filters-uri=http\://simple-opa.default.svc.cluster.local\:8081/v1/data/my-product/rowFilters"#));
        assert!(access_control_config.contains(r#"opa.policy.uri=http\://simple-opa.default.svc.cluster.local\:8081/v1/data/my-product/allow"#));
    }

    #[test]
    fn test_env_overrides() {
        let trino_yaml = r#"
        apiVersion: trino.stackable.tech/v1alpha1
        kind: TrinoCluster
        metadata:
          name: trino
          namespace: default
          uid: "e6ac237d-a6d4-43a1-8135-f36506110912"
        spec:
          image:
            productVersion: "479"
          clusterConfig:
            catalogLabelSelector:
              matchLabels:
                trino: simple-trino
          coordinators:
            envOverrides:
              COMMON_VAR: role-value # overridden by role group below
              ROLE_VAR: role-value   # only defined here at role level
            roleGroups:
              default:
                envOverrides:
                  COMMON_VAR: group-value # overrides role value
                  GROUP_VAR: group-value # only defined here at group level
                replicas: 1
          workers:
            roleGroups:
              default:
                replicas: 1
        "#;
        let deserializer = serde_yaml::Deserializer::from_str(trino_yaml);
        let trino: v1alpha1::TrinoCluster =
            serde_yaml::with::singleton_map_recursive::deserialize(deserializer).unwrap();

        let derefs = DereferencedObjects {
            resolved_authentication_classes: Vec::new(),
            catalog_definitions: Vec::new(),
            catalogs: Vec::new(),
            trino_opa_config: None,
            resolved_fte_config: None,
            resolved_client_protocol_config: None,
        };
        let operator_env = OperatorEnvironmentOptions {
            operator_namespace: "stackable-operators".to_string(),
            operator_service_name: "trino-operator".to_string(),
            image_repository: "oci.example.org".to_string(),
        };
        let validated_cluster =
            validate::validate(&trino, &derefs, &operator_env).expect("validate should succeed");

        let env = &validated_cluster.role_group_configs[&TrinoRole::Coordinator]
            .values()
            .next()
            .unwrap()
            .env_overrides;
        let value = |name: &str| {
            env.get(&EnvVarName::from_str_unsafe(name))
                .and_then(|env_var| env_var.value.clone())
        };
        assert_eq!(value("COMMON_VAR").as_deref(), Some("group-value"));
        assert_eq!(value("GROUP_VAR").as_deref(), Some("group-value"));
        assert_eq!(value("ROLE_VAR").as_deref(), Some("role-value"));
    }
}
