//! Ensures that `Pod`s are configured and running for each [`v1alpha1::TrinoCluster`]
use std::{collections::BTreeMap, convert::Infallible, sync::Arc};

use const_format::concatcp;
use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::{
    builder::{
        configmap::ConfigMapBuilder,
        meta::ObjectMetaBuilder,
        pod::{
            PodBuilder,
            container::ContainerBuilder,
            resources::ResourceRequirementsBuilder,
            security::PodSecurityContextBuilder,
            volume::{SecretFormat, SecretOperatorVolumeSourceBuilder, VolumeBuilder},
        },
    },
    cli::OperatorEnvironmentOptions,
    cluster_resources::{ClusterResourceApplyStrategy, ClusterResources},
    commons::{
        product_image_selection::ResolvedProductImage, random_secret_creation,
        rbac::build_rbac_resources, secret_class::SecretClassVolumeProvisionParts,
    },
    constants::RESTART_CONTROLLER_ENABLED_LABEL,
    k8s_openapi::{
        DeepMerge,
        api::{
            apps::v1::{StatefulSet, StatefulSetSpec},
            core::v1::{
                ConfigMap, ConfigMapVolumeSource, ContainerPort, EnvVar, EnvVarSource, ExecAction,
                HTTPGetAction, Probe, SecretKeySelector, Volume,
            },
        },
        apimachinery::pkg::{apis::meta::v1::LabelSelector, util::intstr::IntOrString},
    },
    kube::{
        Resource, ResourceExt,
        core::{DeserializeGuard, error_boundary},
        runtime::controller::Action,
    },
    kvp::{Annotation, Annotations, Labels, ObjectLabels},
    logging::controller::ReconcilerError,
    memory::{BinaryMultiple, MemoryQuantity},
    product_logging::{
        self,
        framework::LoggingError,
        spec::{
            ConfigMapLogConfig, ContainerLogConfig, ContainerLogConfigChoice,
            CustomContainerLogConfig,
        },
    },
    role_utils::{GenericRoleConfig, RoleGroupRef},
    shared::time::Duration,
    status::condition::{
        compute_conditions, operations::ClusterOperationsConditionBuilder,
        statefulset::StatefulSetConditionBuilder,
    },
    v2::builder::pod::container::EnvVarSet,
};
use strum::{EnumDiscriminants, IntoStaticStr};

mod build;
mod dereference;
mod validate;

use stackable_operator::v2::config_file_writer::to_java_properties_string;
pub use validate::{TrinoRoleGroupConfig, ValidatedCluster};

use crate::{
    authentication::TrinoAuthenticationConfig,
    authorization::opa::{OPA_TLS_VOLUME_NAME, TrinoOpaConfig},
    catalog::config::CatalogConfig,
    command,
    config::{client_protocol, fault_tolerant_execution},
    crd::{
        APP_NAME, CONFIG_DIR_NAME, Container, ENV_INTERNAL_SECRET, ENV_SPOOLING_SECRET, HTTP_PORT,
        HTTP_PORT_NAME, HTTPS_PORT, HTTPS_PORT_NAME, MAX_TRINO_LOG_FILES_SIZE, METRICS_PORT,
        METRICS_PORT_NAME, RW_CONFIG_DIR_NAME, STACKABLE_CLIENT_TLS_DIR,
        STACKABLE_INTERNAL_TLS_DIR, STACKABLE_MOUNT_INTERNAL_TLS_DIR,
        STACKABLE_MOUNT_SERVER_TLS_DIR, STACKABLE_SERVER_TLS_DIR, STACKABLE_TLS_STORE_PASSWORD,
        TrinoRole, v1alpha1,
    },
    listener::{
        LISTENER_VOLUME_DIR, LISTENER_VOLUME_NAME, build_group_listener, build_group_listener_pvc,
        group_listener_name, secret_volume_listener_scope,
    },
    operations::pdb::add_pdbs,
    service::{build_rolegroup_headless_service, build_rolegroup_metrics_service},
};

pub struct Ctx {
    pub client: stackable_operator::client::Client,
    pub operator_environment: OperatorEnvironmentOptions,
}

pub const OPERATOR_NAME: &str = "trino.stackable.tech";
pub const CONTROLLER_NAME: &str = "trinocluster";
pub const FULL_CONTROLLER_NAME: &str = concatcp!(CONTROLLER_NAME, '.', OPERATOR_NAME);

pub const STACKABLE_LOG_DIR: &str = "/stackable/log";
pub const STACKABLE_LOG_CONFIG_DIR: &str = "/stackable/log_config";

pub const MAX_PREPARE_LOG_FILE_SIZE: MemoryQuantity = MemoryQuantity {
    value: 1.0,
    unit: BinaryMultiple::Mebi,
};

pub(super) const CONTAINER_IMAGE_BASE_NAME: &str = "trino";

#[derive(Snafu, Debug, EnumDiscriminants)]
#[strum_discriminants(derive(IntoStaticStr))]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[snafu(display("missing secret lifetime"))]
    MissingSecretLifetime,

    #[snafu(display("failed to create cluster resources"))]
    CreateClusterResources {
        source: stackable_operator::cluster_resources::Error,
    },

    #[snafu(display("failed to delete orphaned resources"))]
    DeleteOrphanedResources {
        source: stackable_operator::cluster_resources::Error,
    },

    #[snafu(display("failed to apply Service for {}", rolegroup))]
    ApplyRoleGroupService {
        source: stackable_operator::cluster_resources::Error,
        rolegroup: RoleGroupRef<v1alpha1::TrinoCluster>,
    },

    #[snafu(display("failed to build ConfigMap for {}", rolegroup))]
    BuildRoleGroupConfig {
        source: stackable_operator::builder::configmap::Error,
        rolegroup: RoleGroupRef<v1alpha1::TrinoCluster>,
    },

    #[snafu(display("failed to build ConfigMap for {}", rolegroup))]
    BuildRoleGroupConfigMap {
        source: build::config_map::Error,
        rolegroup: RoleGroupRef<v1alpha1::TrinoCluster>,
    },

    #[snafu(display("failed to apply ConfigMap for {}", rolegroup))]
    ApplyRoleGroupConfig {
        source: stackable_operator::cluster_resources::Error,
        rolegroup: RoleGroupRef<v1alpha1::TrinoCluster>,
    },

    #[snafu(display("failed to apply StatefulSet for {}", rolegroup))]
    ApplyRoleGroupStatefulSet {
        source: stackable_operator::cluster_resources::Error,
        rolegroup: RoleGroupRef<v1alpha1::TrinoCluster>,
    },

    #[snafu(display("object is missing metadata to build owner reference"))]
    ObjectMissingMetadataForOwnerRef {
        source: stackable_operator::builder::meta::Error,
    },

    #[snafu(display("failed to format runtime properties"))]
    FailedToWriteJavaProperties {
        source: stackable_operator::v2::config_file_writer::PropertiesWriterError,
    },

    #[snafu(display("internal operator failure: {source}"))]
    InternalOperatorFailure { source: crate::crd::Error },

    #[snafu(display("illegal container name: [{container_name}]"))]
    IllegalContainerName {
        source: stackable_operator::builder::pod::container::Error,
        container_name: String,
    },

    #[snafu(display("vector agent is enabled but vector aggregator ConfigMap is missing"))]
    VectorAggregatorConfigMapMissing,

    #[snafu(display("failed to build vector container"))]
    BuildVectorContainer { source: LoggingError },

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

    #[snafu(display("failed to create PodDisruptionBudget"))]
    FailedToCreatePdb {
        source: crate::operations::pdb::Error,
    },

    #[snafu(display("failed to configure graceful shutdown"))]
    GracefulShutdown {
        source: build::graceful_shutdown::Error,
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

    #[snafu(display("failed to build Annotation"))]
    AnnotationBuild {
        source: stackable_operator::kvp::KeyValuePairError<Infallible>,
    },

    #[snafu(display("failed to build Metadata"))]
    MetadataBuild {
        source: stackable_operator::builder::meta::Error,
    },

    #[snafu(display("failed to build TLS certificate SecretClass Volume"))]
    TlsCertSecretClassVolumeBuild {
        source: stackable_operator::builder::pod::volume::SecretOperatorVolumeSourceBuilderError,
    },

    #[snafu(display("failed to add needed volume"))]
    AddVolume {
        source: stackable_operator::builder::pod::Error,
    },

    #[snafu(display("failed to add needed volumeMount"))]
    AddVolumeMount {
        source: stackable_operator::builder::pod::container::Error,
    },

    #[snafu(display("invalid TrinoCluster object"))]
    InvalidTrinoCluster {
        source: error_boundary::InvalidObject,
    },

    #[snafu(display("failed to dereference resources"))]
    Dereference { source: dereference::Error },

    #[snafu(display("failed to validate cluster"))]
    ValidateCluster { source: validate::Error },

    #[snafu(display("invalid Trino authentication"))]
    InvalidAuthenticationConfig {
        source: crate::authentication::Error,
    },

    #[snafu(display("failed to apply group listener"))]
    ApplyGroupListener {
        source: stackable_operator::cluster_resources::Error,
    },

    #[snafu(display("failed to configure listener"))]
    ListenerConfiguration { source: crate::listener::Error },

    #[snafu(display("failed to configure service"))]
    ServiceConfiguration { source: crate::service::Error },

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

    let mut cluster_resources = ClusterResources::new(
        APP_NAME,
        OPERATOR_NAME,
        CONTROLLER_NAME,
        &trino.object_ref(&()),
        ClusterResourceApplyStrategy::from(&trino.spec.cluster_operation),
        &trino.spec.object_overrides,
    )
    .context(CreateClusterResourcesSnafu)?;

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
        &shared_internal_secret_name(trino),
        ENV_INTERNAL_SECRET,
        512,
        trino,
        client,
    )
    .await
    .context(CreateInternalSecretSnafu)?;

    // This secret is created even if spooling is not configured.
    // Trino currently requires the secret to be exactly 256 bits long.
    random_secret_creation::create_random_secret_if_not_exists(
        &shared_spooling_secret_name(trino),
        ENV_SPOOLING_SECRET,
        32,
        trino,
        client,
    )
    .await
    .context(CreateInternalSecretSnafu)?;

    let mut sts_cond_builder = StatefulSetConditionBuilder::default();

    for (trino_role, role_group_configs) in &validated_cluster.role_group_configs {
        for (role_group_name, rg) in role_group_configs {
            let role_group_ref = trino_role.rolegroup_ref(trino, role_group_name);
            let merged_config = &rg.config;

            let role_group_service_recommended_labels = build_recommended_labels(
                trino,
                &validated_cluster.image.app_version_label_value,
                &role_group_ref.role,
                &role_group_ref.role_group,
            );

            let role_group_service_selector = Labels::role_group_selector(
                trino,
                APP_NAME,
                &role_group_ref.role,
                &role_group_ref.role_group,
            )
            .context(LabelBuildSnafu)?;

            let rg_headless_service = build_rolegroup_headless_service(
                trino,
                &role_group_ref,
                &role_group_service_recommended_labels,
                role_group_service_selector.clone().into(),
            )
            .context(ServiceConfigurationSnafu)?;

            let rg_metrics_service = build_rolegroup_metrics_service(
                trino,
                &role_group_ref,
                &role_group_service_recommended_labels,
                role_group_service_selector.into(),
            )
            .context(ServiceConfigurationSnafu)?;

            let rg_configmap = build::config_map::build_rolegroup_config_map(
                &validated_cluster,
                trino_role,
                &role_group_ref,
                &client.kubernetes_cluster_info,
                &role_group_service_recommended_labels,
            )
            .with_context(|_| BuildRoleGroupConfigMapSnafu {
                rolegroup: role_group_ref.clone(),
            })?;

            let rg_catalog_configmap = build_rolegroup_catalog_config_map(
                trino,
                &validated_cluster.image,
                &role_group_ref,
                &validated_cluster.cluster_config.catalogs,
            )?;

            let rg_stateful_set = build_rolegroup_statefulset(
                trino,
                trino_role,
                &validated_cluster.image,
                &role_group_ref,
                &rg.env_overrides,
                merged_config,
                &validated_cluster.cluster_config.authentication,
                &validated_cluster.cluster_config.catalogs,
                &rbac_sa.name_any(),
                &validated_cluster.cluster_config.fault_tolerant_execution,
                &validated_cluster.cluster_config.client_protocol,
                &validated_cluster.cluster_config.authorization,
            )?;

            cluster_resources
                .add(client, rg_headless_service)
                .await
                .with_context(|_| ApplyRoleGroupServiceSnafu {
                    rolegroup: role_group_ref.clone(),
                })?;

            cluster_resources
                .add(client, rg_metrics_service)
                .await
                .with_context(|_| ApplyRoleGroupServiceSnafu {
                    rolegroup: role_group_ref.clone(),
                })?;

            cluster_resources
                .add(client, rg_configmap)
                .await
                .with_context(|_| ApplyRoleGroupConfigSnafu {
                    rolegroup: role_group_ref.clone(),
                })?;

            cluster_resources
                .add(client, rg_catalog_configmap)
                .await
                .with_context(|_| ApplyRoleGroupConfigSnafu {
                    rolegroup: role_group_ref.clone(),
                })?;

            // Note: The StatefulSet needs to be applied after all ConfigMaps and Secrets it mounts
            // to prevent unnecessary Pod restarts.
            // See https://github.com/stackabletech/commons-operator/issues/111 for details.
            sts_cond_builder.add(
                cluster_resources
                    .add(client, rg_stateful_set)
                    .await
                    .with_context(|_| ApplyRoleGroupStatefulSetSnafu {
                        rolegroup: role_group_ref.clone(),
                    })?,
            );
        }

        if let Some(listener_class) = trino_role.listener_class_name(trino) {
            if let Some(listener_group_name) = group_listener_name(trino, trino_role) {
                let role_group_listener = build_group_listener(
                    trino,
                    build_recommended_labels(
                        trino,
                        &validated_cluster.image.app_version_label_value,
                        &trino_role.to_string(),
                        "none",
                    ),
                    listener_class.to_string(),
                    listener_group_name,
                )
                .context(ListenerConfigurationSnafu)?;

            cluster_resources
                .add(client, role_group_listener)
                .await
                .context(ApplyGroupListenerSnafu)?;
        }

        let role_config = trino.generic_role_config(trino_role);
        if let Some(GenericRoleConfig {
            pod_disruption_budget: pdb,
        }) = role_config
        {
            add_pdbs(pdb, trino, trino_role, client, &mut cluster_resources)
                .await
                .context(FailedToCreatePdbSnafu)?;
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

/// The rolegroup catalog [`ConfigMap`] configures the rolegroup catalog based on the configuration
/// given by the administrator
fn build_rolegroup_catalog_config_map(
    trino: &v1alpha1::TrinoCluster,
    resolved_product_image: &ResolvedProductImage,
    rolegroup_ref: &RoleGroupRef<v1alpha1::TrinoCluster>,
    catalogs: &[CatalogConfig],
) -> Result<ConfigMap> {
    ConfigMapBuilder::new()
        .metadata(
            ObjectMetaBuilder::new()
                .name_and_namespace(trino)
                .name(format!("{}-catalog", rolegroup_ref.object_name()))
                .ownerreference_from_resource(trino, None, Some(true))
                .context(ObjectMissingMetadataForOwnerRefSnafu)?
                .with_recommended_labels(&build_recommended_labels(
                    trino,
                    &resolved_product_image.app_version_label_value,
                    &rolegroup_ref.role,
                    &rolegroup_ref.role_group,
                ))
                .context(MetadataBuildSnafu)?
                .build(),
        )
        .data(
            catalogs
                .iter()
                .map(|catalog| {
                    Ok((
                        format!("{}.properties", catalog.name),
                        to_java_properties_string(catalog.properties.iter())
                            .context(FailedToWriteJavaPropertiesSnafu)?,
                    ))
                })
                .collect::<Result<_>>()?,
        )
        .build()
        .with_context(|_| BuildRoleGroupConfigSnafu {
            rolegroup: rolegroup_ref.clone(),
        })
}

/// The rolegroup [`StatefulSet`] runs the rolegroup, as configured by the administrator.
///
/// The [`Pod`](`stackable_operator::k8s_openapi::api::core::v1::Pod`)s are accessible through the
/// corresponding [`stackable_operator::k8s_openapi::api::core::v1::Service`] (from [`build_rolegroup_headless_service`]).
#[allow(clippy::too_many_arguments)]
fn build_rolegroup_statefulset(
    trino: &v1alpha1::TrinoCluster,
    trino_role: &TrinoRole,
    resolved_product_image: &ResolvedProductImage,
    role_group_ref: &RoleGroupRef<v1alpha1::TrinoCluster>,
    env_overrides: &EnvVarSet,
    merged_config: &v1alpha1::TrinoConfig,
    trino_authentication_config: &TrinoAuthenticationConfig,
    catalogs: &[CatalogConfig],
    sa_name: &str,
    resolved_fte_config: &Option<fault_tolerant_execution::ResolvedFaultTolerantExecutionConfig>,
    resolved_spooling_config: &Option<client_protocol::ResolvedClientProtocolConfig>,
    trino_opa_config: &Option<TrinoOpaConfig>,
) -> Result<StatefulSet> {
    let role = trino
        .role(trino_role)
        .context(InternalOperatorFailureSnafu)?;
    let rolegroup = trino
        .rolegroup(role_group_ref)
        .context(InternalOperatorFailureSnafu)?;

    let mut pod_builder = PodBuilder::new();

    let prepare_container_name = Container::Prepare.to_string();
    let mut cb_prepare = ContainerBuilder::new(&prepare_container_name).with_context(|_| {
        IllegalContainerNameSnafu {
            container_name: prepare_container_name.clone(),
        }
    })?;

    let trino_container_name = Container::Trino.to_string();
    let mut cb_trino = ContainerBuilder::new(&trino_container_name).with_context(|_| {
        IllegalContainerNameSnafu {
            container_name: trino_container_name.clone(),
        }
    })?;

    // additional authentication env vars
    let mut env = trino_authentication_config.env_vars(trino_role, &Container::Trino);

    let internal_secret_name = shared_internal_secret_name(trino);
    env.push(env_var_from_secret(
        &internal_secret_name,
        None,
        ENV_INTERNAL_SECRET,
    ));

    let spooling_secret_name = shared_spooling_secret_name(trino);
    env.push(env_var_from_secret(
        &spooling_secret_name,
        None,
        ENV_SPOOLING_SECRET,
    ));

    trino_authentication_config
        .add_authentication_pod_and_volume_config(
            trino_role,
            &mut pod_builder,
            &mut cb_prepare,
            &mut cb_trino,
        )
        .context(InvalidAuthenticationConfigSnafu)?;
    build::graceful_shutdown::add_graceful_shutdown_config(
        trino,
        trino_role,
        merged_config,
        &mut pod_builder,
        &mut cb_trino,
    )
    .context(GracefulShutdownSnafu)?;

    // Add the needed stuff for catalogs
    env.extend(
        catalogs
            .iter()
            .flat_map(|catalog| &catalog.env_bindings)
            .cloned(),
    );

    // Needed by the `containerdebug` process to log it's tracing information to.
    // This process runs in the background of the `trino` container.
    // See command::container_trino_args() for how it's called.
    env.push(EnvVar {
        name: "CONTAINERDEBUG_LOG_DIRECTORY".into(),
        value: Some(format!("{STACKABLE_LOG_DIR}/containerdebug")),
        ..EnvVar::default()
    });

    // Finally add the user defined envOverrides properties.
    env.extend(env_overrides.clone());

    let requested_secret_lifetime = merged_config
        .requested_secret_lifetime
        .context(MissingSecretLifetimeSnafu)?;

    // add volume mounts depending on the client tls, internal tls, catalogs and authentication
    tls_volume_mounts(
        trino,
        trino_role,
        &mut pod_builder,
        &mut cb_prepare,
        &mut cb_trino,
        catalogs,
        &requested_secret_lifetime,
        resolved_fte_config,
        resolved_spooling_config,
        trino_opa_config,
    )?;

    let mut prepare_args = vec![];
    if let Some(ContainerLogConfig {
        choice: Some(ContainerLogConfigChoice::Automatic(log_config)),
    }) = merged_config.logging.containers.get(&Container::Prepare)
    {
        prepare_args.push(product_logging::framework::capture_shell_output(
            STACKABLE_LOG_DIR,
            &prepare_container_name,
            log_config,
        ));
    }

    prepare_args.extend(command::container_prepare_args(
        trino,
        catalogs,
        merged_config,
        resolved_fte_config,
        resolved_spooling_config,
    ));

    prepare_args
        .extend(trino_authentication_config.commands(&TrinoRole::Coordinator, &Container::Prepare));

    // Add OPA TLS certificate to truststore if configured
    if let Some(tls_mount_path) = trino_opa_config
        .as_ref()
        .and_then(|opa_config| opa_config.tls_mount_path())
    {
        prepare_args.extend(command::add_cert_to_truststore(
            format!("{}/ca.crt", tls_mount_path).as_str(),
            STACKABLE_CLIENT_TLS_DIR,
        ));
    }

    let container_prepare = cb_prepare
        .image_from_product_image(resolved_product_image)
        .command(vec![
            "/bin/bash".to_string(),
            "-x".to_string(),
            "-euo".to_string(),
            "pipefail".to_string(),
            "-c".to_string(),
        ])
        .args(vec![prepare_args.join("\n")])
        .add_volume_mount("rwconfig", RW_CONFIG_DIR_NAME)
        .context(AddVolumeMountSnafu)?
        .add_volume_mount("log-config", STACKABLE_LOG_CONFIG_DIR)
        .context(AddVolumeMountSnafu)?
        .add_volume_mount("log", STACKABLE_LOG_DIR)
        .context(AddVolumeMountSnafu)?
        .resources(
            ResourceRequirementsBuilder::new()
                .with_cpu_request("500m")
                .with_cpu_limit("2000m")
                .with_memory_request("4Gi")
                .with_memory_limit("4Gi")
                .build(),
        )
        .build();

    let mut persistent_volume_claims = vec![];
    // Add listener
    if let Some(group_listener_name) = group_listener_name(trino, trino_role) {
        cb_trino
            .add_volume_mount(LISTENER_VOLUME_NAME, LISTENER_VOLUME_DIR)
            .context(AddVolumeMountSnafu)?;

        // Used for PVC templates that cannot be modified once they are deployed
        let unversioned_recommended_labels = Labels::recommended(&build_recommended_labels(
            trino,
            // A version value is required, and we do want to use the "recommended" format for the other desired labels
            "none",
            &role_group_ref.role,
            &role_group_ref.role_group,
        ))
        .context(LabelBuildSnafu)?;

        persistent_volume_claims.push(
            build_group_listener_pvc(&group_listener_name, &unversioned_recommended_labels)
                .context(ListenerConfigurationSnafu)?,
        );
    }

    let container_trino = cb_trino
        .image_from_product_image(resolved_product_image)
        .command(vec![
            "/bin/bash".to_string(),
            "-x".to_string(),
            "-euo".to_string(),
            "pipefail".to_string(),
            "-c".to_string(),
        ])
        .args(vec![
            command::container_trino_args(trino_authentication_config, catalogs).join("\n"),
        ])
        .add_env_vars(env)
        .add_volume_mount("config", CONFIG_DIR_NAME)
        .context(AddVolumeMountSnafu)?
        .add_volume_mount("rwconfig", RW_CONFIG_DIR_NAME)
        .context(AddVolumeMountSnafu)?
        .add_volume_mount("catalog", format!("{}/catalog", CONFIG_DIR_NAME))
        .context(AddVolumeMountSnafu)?
        .add_volume_mount("log", STACKABLE_LOG_DIR)
        .context(AddVolumeMountSnafu)?
        .add_container_ports(container_ports(trino))
        .resources(merged_config.resources.clone().into())
        // The probes are set on coordinators and workers
        .startup_probe(startup_probe(trino))
        .readiness_probe(readiness_probe(trino))
        .liveness_probe(liveness_probe(trino))
        .build();

    // add trino container first to better default into that container (e.g. instead of vector)
    pod_builder.add_container(container_trino);

    // add password-update container if required
    trino_authentication_config.add_authentication_containers(trino_role, &mut pod_builder);

    if let Some(ContainerLogConfig {
        choice:
            Some(ContainerLogConfigChoice::Custom(CustomContainerLogConfig {
                custom: ConfigMapLogConfig { config_map },
            })),
    }) = merged_config.logging.containers.get(&Container::Trino)
    {
        pod_builder
            .add_volume(Volume {
                name: "log-config".to_string(),
                config_map: Some(ConfigMapVolumeSource {
                    name: config_map.into(),
                    ..ConfigMapVolumeSource::default()
                }),
                ..Volume::default()
            })
            .context(AddVolumeSnafu)?;
    } else {
        pod_builder
            .add_volume(Volume {
                name: "log-config".to_string(),
                config_map: Some(ConfigMapVolumeSource {
                    name: role_group_ref.object_name(),
                    ..ConfigMapVolumeSource::default()
                }),
                ..Volume::default()
            })
            .context(AddVolumeSnafu)?;
    }

    if merged_config.logging.enable_vector_agent {
        match &trino.spec.cluster_config.vector_aggregator_config_map_name {
            Some(vector_aggregator_config_map_name) => {
                pod_builder.add_container(
                    product_logging::framework::vector_container(
                        resolved_product_image,
                        "config",
                        "log",
                        merged_config.logging.containers.get(&Container::Vector),
                        ResourceRequirementsBuilder::new()
                            .with_cpu_request("250m")
                            .with_cpu_limit("500m")
                            .with_memory_request("128Mi")
                            .with_memory_limit("128Mi")
                            .build(),
                        vector_aggregator_config_map_name,
                    )
                    .context(BuildVectorContainerSnafu)?,
                );
            }
            None => {
                VectorAggregatorConfigMapMissingSnafu.fail()?;
            }
        }
    }

    let metadata = ObjectMetaBuilder::new()
        .with_recommended_labels(&build_recommended_labels(
            trino,
            &resolved_product_image.app_version_label_value,
            &role_group_ref.role,
            &role_group_ref.role_group,
        ))
        .context(MetadataBuildSnafu)?
        .with_annotation(
            // This is actually used by some kuttl tests (as they don't specify the container explicitly)
            Annotation::try_from(("kubectl.kubernetes.io/default-container", "trino"))
                .context(AnnotationBuildSnafu)?,
        )
        .build();

    pod_builder
        .metadata(metadata)
        .image_pull_secrets_from_product_image(resolved_product_image)
        .affinity(&merged_config.affinity)
        .add_init_container(container_prepare)
        .add_volume(Volume {
            name: "config".to_string(),
            config_map: Some(ConfigMapVolumeSource {
                name: role_group_ref.object_name(),
                ..ConfigMapVolumeSource::default()
            }),
            ..Volume::default()
        })
        .context(AddVolumeSnafu)?
        .add_empty_dir_volume("rwconfig", None)
        .context(AddVolumeSnafu)?
        .add_volume(Volume {
            name: "catalog".to_string(),
            config_map: Some(ConfigMapVolumeSource {
                name: format!("{}-catalog", role_group_ref.object_name()),
                ..ConfigMapVolumeSource::default()
            }),
            ..Volume::default()
        })
        .context(AddVolumeSnafu)?
        .add_empty_dir_volume(
            "log",
            Some(product_logging::framework::calculate_log_volume_size_limit(
                &[MAX_TRINO_LOG_FILES_SIZE, MAX_PREPARE_LOG_FILE_SIZE],
            )),
        )
        .context(AddVolumeSnafu)?
        .service_account_name(sa_name)
        .security_context(PodSecurityContextBuilder::new().fs_group(1000).build());

    let mut pod_template = pod_builder.build_template();
    pod_template.merge_from(role.config.pod_overrides.clone());
    pod_template.merge_from(rolegroup.config.pod_overrides.clone());

    let ignore_secret_annotations = trino_authentication_config
        .hot_reloaded_secrets()
        .iter()
        .enumerate()
        .map(|(i, secret_name)| {
            (
                format!("restarter.stackable.tech/ignore-secret.{i}"),
                secret_name,
            )
        })
        .collect::<BTreeMap<_, _>>();

    let annotations =
        Annotations::try_from(ignore_secret_annotations).context(AnnotationBuildSnafu)?;

    Ok(StatefulSet {
        metadata: ObjectMetaBuilder::new()
            .name_and_namespace(trino)
            .name(role_group_ref.object_name())
            .ownerreference_from_resource(trino, None, Some(true))
            .context(ObjectMissingMetadataForOwnerRefSnafu)?
            .with_recommended_labels(&build_recommended_labels(
                trino,
                &resolved_product_image.app_version_label_value,
                &role_group_ref.role,
                &role_group_ref.role_group,
            ))
            .context(MetadataBuildSnafu)?
            .with_label(RESTART_CONTROLLER_ENABLED_LABEL.to_owned())
            .with_annotations(annotations)
            .build(),
        spec: Some(StatefulSetSpec {
            pod_management_policy: Some("Parallel".to_string()),
            replicas: rolegroup.replicas.map(i32::from),
            selector: LabelSelector {
                match_labels: Some(
                    Labels::role_group_selector(
                        trino,
                        APP_NAME,
                        &role_group_ref.role,
                        &role_group_ref.role_group,
                    )
                    .context(LabelBuildSnafu)?
                    .into(),
                ),
                ..LabelSelector::default()
            },
            service_name: Some(role_group_ref.rolegroup_headless_service_name()),
            template: pod_template,
            volume_claim_templates: Some(persistent_volume_claims),
            ..StatefulSetSpec::default()
        }),
        status: None,
    })
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

/// Give a secret name and an optional key in the secret to use.
/// The value from the key will be set into the given env var name.
/// If not secret key is given, the env var name will be used as the secret key.
fn env_var_from_secret(secret_name: &str, secret_key: Option<&str>, env_var: &str) -> EnvVar {
    EnvVar {
        name: env_var.to_string(),
        value_from: Some(EnvVarSource {
            secret_key_ref: Some(SecretKeySelector {
                optional: Some(false),
                name: secret_name.to_string(),
                key: secret_key.unwrap_or(env_var).to_string(),
            }),
            ..EnvVarSource::default()
        }),
        ..EnvVar::default()
    }
}

fn build_recommended_labels<'a>(
    owner: &'a v1alpha1::TrinoCluster,
    app_version: &'a str,
    role: &'a str,
    role_group: &'a str,
) -> ObjectLabels<'a, v1alpha1::TrinoCluster> {
    ObjectLabels {
        owner,
        app_name: APP_NAME,
        app_version,
        operator_name: OPERATOR_NAME,
        controller_name: CONTROLLER_NAME,
        role,
        role_group,
    }
}

fn shared_internal_secret_name(trino: &v1alpha1::TrinoCluster) -> String {
    format!("{}-internal-secret", trino.name_any())
}

fn shared_spooling_secret_name(trino: &v1alpha1::TrinoCluster) -> String {
    format!("{}-spooling-secret", trino.name_any())
}

fn container_ports(trino: &v1alpha1::TrinoCluster) -> Vec<ContainerPort> {
    let mut ports = vec![ContainerPort {
        name: Some(METRICS_PORT_NAME.to_string()),
        container_port: METRICS_PORT.into(),
        protocol: Some("TCP".to_string()),
        ..ContainerPort::default()
    }];

    if trino.expose_http_port() {
        ports.push(ContainerPort {
            name: Some(HTTP_PORT_NAME.to_string()),
            container_port: HTTP_PORT.into(),
            protocol: Some("TCP".to_string()),
            ..ContainerPort::default()
        })
    }

    if trino.expose_https_port() {
        ports.push(ContainerPort {
            name: Some(HTTPS_PORT_NAME.to_string()),
            container_port: HTTPS_PORT.into(),
            protocol: Some("TCP".to_string()),
            ..ContainerPort::default()
        });
    }

    ports
}

fn startup_probe(trino: &v1alpha1::TrinoCluster) -> Probe {
    Probe {
        exec: Some(finished_starting_probe(trino)),
        period_seconds: Some(5),
        // Give the coordinator or worker 10 minutes to start up
        failure_threshold: Some(120),
        timeout_seconds: Some(3),
        ..Default::default()
    }
}

fn readiness_probe(trino: &v1alpha1::TrinoCluster) -> Probe {
    Probe {
        http_get: Some(http_get_probe(trino)),
        period_seconds: Some(5),
        failure_threshold: Some(1),
        timeout_seconds: Some(3),
        ..Probe::default()
    }
}

fn liveness_probe(trino: &v1alpha1::TrinoCluster) -> Probe {
    Probe {
        http_get: Some(http_get_probe(trino)),
        period_seconds: Some(5),
        // Coordinators are currently not highly available, so you always have a singe instance.
        // Restarting it causes all queries to fail, so let's not restart it directly after the first
        // probe failure, but wait for 3 failures
        // NOTE: This also applies to workers
        failure_threshold: Some(3),
        timeout_seconds: Some(3),
        ..Probe::default()
    }
}

/// Check that `/v1/info` returns `200`.
///
/// This is the same probe as the [upstream helm-chart](https://github.com/trinodb/charts/blob/7cd0a7bff6c52e0ee6ca6d5394cd72c150ad4379/charts/trino/templates/deployment-coordinator.yaml#L214)
/// is using.
fn http_get_probe(trino: &v1alpha1::TrinoCluster) -> HTTPGetAction {
    let (schema, port_name) = if trino.expose_https_port() {
        ("HTTPS", HTTPS_PORT_NAME)
    } else {
        ("HTTP", HTTP_PORT_NAME)
    };

    HTTPGetAction {
        port: IntOrString::String(port_name.to_string()),
        scheme: Some(schema.to_string()),
        path: Some("/v1/info".to_string()),
        ..Default::default()
    }
}

/// Wait until `/v1/info` returns `"starting":false`.
///
/// This probe works on coordinators and workers.
fn finished_starting_probe(trino: &v1alpha1::TrinoCluster) -> ExecAction {
    let port = trino.exposed_port();
    let schema = if trino.expose_https_port() {
        "https"
    } else {
        "http"
    };

    ExecAction {
        command: Some(vec![
            "/bin/bash".to_string(),
            "-x".to_string(),
            "-euo".to_string(),
            "pipefail".to_string(),
            "-c".to_string(),
            format!(
                "curl --fail --insecure {schema}://127.0.0.1:{port}/v1/info | grep --silent '\\\"starting\\\":false'"
            ),
        ]),
    }
}

fn create_tls_volume(
    volume_name: &str,
    tls_secret_class: &str,
    requested_secret_lifetime: &Duration,
    listener_scope: Option<String>,
) -> Result<Volume> {
    let mut secret_volume_source_builder = SecretOperatorVolumeSourceBuilder::new(
        tls_secret_class,
        SecretClassVolumeProvisionParts::PublicPrivate,
    );

    secret_volume_source_builder
        .with_pod_scope()
        .with_format(SecretFormat::TlsPkcs12)
        .with_tls_pkcs12_password(STACKABLE_TLS_STORE_PASSWORD)
        .with_auto_tls_cert_lifetime(*requested_secret_lifetime);

    if let Some(listener_scope) = &listener_scope {
        secret_volume_source_builder.with_listener_volume_scope(listener_scope);
    }

    Ok(VolumeBuilder::new(volume_name)
        .ephemeral(
            secret_volume_source_builder
                .build()
                .context(TlsCertSecretClassVolumeBuildSnafu)?,
        )
        .build())
}

#[allow(clippy::too_many_arguments)]
fn tls_volume_mounts(
    trino: &v1alpha1::TrinoCluster,
    trino_role: &TrinoRole,
    pod_builder: &mut PodBuilder,
    cb_prepare: &mut ContainerBuilder,
    cb_trino: &mut ContainerBuilder,
    catalogs: &[CatalogConfig],
    requested_secret_lifetime: &Duration,
    resolved_fte_config: &Option<fault_tolerant_execution::ResolvedFaultTolerantExecutionConfig>,
    resolved_spooling_config: &Option<client_protocol::ResolvedClientProtocolConfig>,
    trino_opa_config: &Option<TrinoOpaConfig>,
) -> Result<()> {
    if let Some(server_tls) = trino.get_server_tls() {
        cb_prepare
            .add_volume_mount("server-tls-mount", STACKABLE_MOUNT_SERVER_TLS_DIR)
            .context(AddVolumeMountSnafu)?;
        cb_trino
            .add_volume_mount("server-tls-mount", STACKABLE_MOUNT_SERVER_TLS_DIR)
            .context(AddVolumeMountSnafu)?;
        pod_builder
            .add_volume(create_tls_volume(
                "server-tls-mount",
                server_tls,
                requested_secret_lifetime,
                // add listener
                secret_volume_listener_scope(trino_role),
            )?)
            .context(AddVolumeSnafu)?;
    }

    cb_prepare
        .add_volume_mount("server-tls", STACKABLE_SERVER_TLS_DIR)
        .context(AddVolumeMountSnafu)?;
    cb_trino
        .add_volume_mount("server-tls", STACKABLE_SERVER_TLS_DIR)
        .context(AddVolumeMountSnafu)?;
    pod_builder
        .add_empty_dir_volume("server-tls", None)
        .context(AddVolumeSnafu)?;

    cb_prepare
        .add_volume_mount("client-tls", STACKABLE_CLIENT_TLS_DIR)
        .context(AddVolumeMountSnafu)?;
    cb_trino
        .add_volume_mount("client-tls", STACKABLE_CLIENT_TLS_DIR)
        .context(AddVolumeMountSnafu)?;
    pod_builder
        .add_empty_dir_volume("client-tls", None)
        .context(AddVolumeSnafu)?;

    if let Some(internal_tls) = trino.get_internal_tls() {
        cb_prepare
            .add_volume_mount("internal-tls-mount", STACKABLE_MOUNT_INTERNAL_TLS_DIR)
            .context(AddVolumeMountSnafu)?;
        cb_trino
            .add_volume_mount("internal-tls-mount", STACKABLE_MOUNT_INTERNAL_TLS_DIR)
            .context(AddVolumeMountSnafu)?;
        pod_builder
            .add_volume(create_tls_volume(
                "internal-tls-mount",
                internal_tls,
                requested_secret_lifetime,
                None,
            )?)
            .context(AddVolumeSnafu)?;

        cb_prepare
            .add_volume_mount("internal-tls", STACKABLE_INTERNAL_TLS_DIR)
            .context(AddVolumeMountSnafu)?;
        cb_trino
            .add_volume_mount("internal-tls", STACKABLE_INTERNAL_TLS_DIR)
            .context(AddVolumeMountSnafu)?;
        pod_builder
            .add_empty_dir_volume("internal-tls", None)
            .context(AddVolumeSnafu)?;
    }

    // catalogs
    for catalog in catalogs {
        cb_prepare
            .add_volume_mounts(catalog.volume_mounts.clone())
            .context(AddVolumeMountSnafu)?;
        cb_trino
            .add_volume_mounts(catalog.volume_mounts.clone())
            .context(AddVolumeMountSnafu)?;
        pod_builder
            .add_volumes(catalog.volumes.clone())
            .context(AddVolumeSnafu)?;
    }

    // Add OPA TLS certs if configured
    if let Some((tls_secret_class, tls_mount_path)) =
        trino_opa_config.as_ref().and_then(|opa_config| {
            opa_config
                .tls_secret_class
                .as_ref()
                .zip(opa_config.tls_mount_path())
        })
    {
        cb_prepare
            .add_volume_mount(OPA_TLS_VOLUME_NAME, &tls_mount_path)
            .context(AddVolumeMountSnafu)?;

        let opa_tls_volume = VolumeBuilder::new(OPA_TLS_VOLUME_NAME)
            .ephemeral(
                SecretOperatorVolumeSourceBuilder::new(
                    tls_secret_class,
                    SecretClassVolumeProvisionParts::PublicPrivate,
                )
                .build()
                .context(TlsCertSecretClassVolumeBuildSnafu)?,
            )
            .build();

        pod_builder
            .add_volume(opa_tls_volume)
            .context(AddVolumeSnafu)?;
    }

    // fault tolerant execution S3 credentials and other resources
    if let Some(resolved_fte) = resolved_fte_config {
        cb_prepare
            .add_volume_mounts(resolved_fte.volume_mounts.clone())
            .context(AddVolumeMountSnafu)?;
        cb_trino
            .add_volume_mounts(resolved_fte.volume_mounts.clone())
            .context(AddVolumeMountSnafu)?;
        pod_builder
            .add_volumes(resolved_fte.volumes.clone())
            .context(AddVolumeSnafu)?;
    }

    // client spooling S3 credentials and other resources
    if let Some(resolved_spooling) = resolved_spooling_config {
        cb_prepare
            .add_volume_mounts(resolved_spooling.volume_mounts.clone())
            .context(AddVolumeMountSnafu)?;
        cb_trino
            .add_volume_mounts(resolved_spooling.volume_mounts.clone())
            .context(AddVolumeMountSnafu)?;
        pod_builder
            .add_volumes(resolved_spooling.volumes.clone())
            .context(AddVolumeSnafu)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use stackable_operator::{
        cli::OperatorEnvironmentOptions, commons::networking::DomainName,
        k8s_openapi::api::core::v1::ConfigMap, kube::runtime::reflector::ObjectRef,
        role_utils::RoleGroupRef, utils::cluster_info::KubernetesClusterInfo,
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
        // For OPA, the legacy helper used a hard-coded `TrinoOpaConfig` literal
        // rather than resolving from cluster config; mirror that here so that
        // `test_access_control_overrides` does not need a Kubernetes client and
        // so that `test_config_overrides` keeps observing an
        // `access-control.properties` entry in the rendered ConfigMap.
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
        let rolegroup_ref = RoleGroupRef {
            cluster: ObjectRef::from_obj(&trino),
            role: trino_role.to_string(),
            role_group: "default".to_string(),
        };
        let recommended_labels = build_recommended_labels(
            &trino,
            &validated_cluster.image.app_version_label_value,
            &rolegroup_ref.role,
            &rolegroup_ref.role_group,
        );

        build::config_map::build_rolegroup_config_map(
            &validated_cluster,
            &trino_role,
            &rolegroup_ref,
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

        let env =
            &validated_cluster.role_group_configs[&TrinoRole::Coordinator]["default"].env_overrides;
        let value = |name: &str| {
            env.get(&EnvVarName::from_str_unsafe(name))
                .and_then(|env_var| env_var.value.clone())
        };
        assert_eq!(value("COMMON_VAR").as_deref(), Some("group-value"));
        assert_eq!(value("GROUP_VAR").as_deref(), Some("group-value"));
        assert_eq!(value("ROLE_VAR").as_deref(), Some("role-value"));
    }
}
