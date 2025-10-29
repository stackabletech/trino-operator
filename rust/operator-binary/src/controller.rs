//! Ensures that `Pod`s are configured and running for each [`v1alpha1::TrinoCluster`]
use std::{
    collections::{BTreeMap, HashMap},
    convert::Infallible,
    num::ParseIntError,
    str::FromStr,
    sync::Arc,
};

use const_format::concatcp;
use product_config::{
    self, ProductConfigManager,
    types::PropertyNameKind,
    writer::{PropertiesWriterError, to_java_properties_string},
};
use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::{
    builder::{
        self,
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
    client::Client,
    cluster_resources::{ClusterResourceApplyStrategy, ClusterResources},
    commons::{
        product_image_selection::{self, ResolvedProductImage},
        rbac::build_rbac_resources,
    },
    k8s_openapi::{
        DeepMerge,
        api::{
            apps::v1::{StatefulSet, StatefulSetSpec},
            core::v1::{
                ConfigMap, ConfigMapVolumeSource, ContainerPort, EnvVar, EnvVarSource, ExecAction,
                HTTPGetAction, Probe, Secret, SecretKeySelector, Volume,
            },
        },
        apimachinery::pkg::{apis::meta::v1::LabelSelector, util::intstr::IntOrString},
    },
    kube::{
        Resource, ResourceExt,
        core::{DeserializeGuard, error_boundary},
        runtime::{controller::Action, reflector::ObjectRef},
    },
    kvp::{Annotation, Labels, ObjectLabels},
    logging::controller::ReconcilerError,
    memory::{BinaryMultiple, MemoryQuantity},
    product_config_utils::{
        ValidatedRoleConfigByPropertyKind, transform_all_roles_to_config,
        validate_all_roles_and_groups_config,
    },
    product_logging::{
        self,
        framework::LoggingError,
        spec::{
            ConfigMapLogConfig, ContainerLogConfig, ContainerLogConfigChoice,
            CustomContainerLogConfig,
        },
    },
    role_utils::{GenericRoleConfig, JavaCommonConfig, Role, RoleGroupRef},
    shared::time::Duration,
    status::condition::{
        compute_conditions, operations::ClusterOperationsConditionBuilder,
        statefulset::StatefulSetConditionBuilder,
    },
    utils::cluster_info::KubernetesClusterInfo,
};
use strum::{EnumDiscriminants, IntoStaticStr};

use crate::{
    authentication::{TrinoAuthenticationConfig, TrinoAuthenticationTypes},
    authorization::opa::TrinoOpaConfig,
    catalog::{FromTrinoCatalogError, config::CatalogConfig},
    command, config,
    config::{client_protocol, fault_tolerant_execution},
    crd::{
        ACCESS_CONTROL_PROPERTIES, APP_NAME, CONFIG_DIR_NAME, CONFIG_PROPERTIES, Container,
        DISCOVERY_URI, ENV_INTERNAL_SECRET, ENV_SPOOLING_SECRET, EXCHANGE_MANAGER_PROPERTIES,
        HTTP_PORT, HTTP_PORT_NAME, HTTPS_PORT, HTTPS_PORT_NAME, JVM_CONFIG,
        JVM_SECURITY_PROPERTIES, LOG_PROPERTIES, MAX_TRINO_LOG_FILES_SIZE, METRICS_PORT,
        METRICS_PORT_NAME, NODE_PROPERTIES, RW_CONFIG_DIR_NAME, SPOOLING_MANAGER_PROPERTIES,
        STACKABLE_CLIENT_TLS_DIR, STACKABLE_INTERNAL_TLS_DIR, STACKABLE_MOUNT_INTERNAL_TLS_DIR,
        STACKABLE_MOUNT_SERVER_TLS_DIR, STACKABLE_SERVER_TLS_DIR, STACKABLE_TLS_STORE_PASSWORD,
        TrinoRole,
        authentication::resolve_authentication_classes,
        catalog,
        discovery::{TrinoDiscovery, TrinoDiscoveryProtocol, TrinoPodRef},
        v1alpha1,
    },
    listener::{
        LISTENER_VOLUME_DIR, LISTENER_VOLUME_NAME, build_group_listener, build_group_listener_pvc,
        group_listener_name, secret_volume_listener_scope,
    },
    operations::{
        add_graceful_shutdown_config, graceful_shutdown_config_properties, pdb::add_pdbs,
    },
    product_logging::{get_log_properties, get_vector_toml},
    service::{build_rolegroup_headless_service, build_rolegroup_metrics_service},
};

pub struct Ctx {
    pub client: stackable_operator::client::Client,
    pub product_config: ProductConfigManager,
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

const DOCKER_IMAGE_BASE_NAME: &str = "trino";
const OPA_TLS_VOLUME_NAME: &str = "opa-tls";

#[derive(Snafu, Debug, EnumDiscriminants)]
#[strum_discriminants(derive(IntoStaticStr))]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[snafu(display("missing secret lifetime"))]
    MissingSecretLifetime,

    #[snafu(display("object defines no namespace"))]
    ObjectHasNoNamespace,

    #[snafu(display("trino cluster {name:?} has no namespace"))]
    MissingTrinoNamespace {
        source: crate::crd::Error,
        name: String,
    },

    #[snafu(display("object defines no {role:?} role"))]
    MissingTrinoRole {
        source: crate::crd::Error,
        role: String,
    },

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

    #[snafu(display("failed to apply internal secret"))]
    ApplyInternalSecret {
        source: stackable_operator::client::Error,
    },

    #[snafu(display("invalid product config"))]
    InvalidProductConfig {
        source: stackable_operator::product_config_utils::Error,
    },

    #[snafu(display("object is missing metadata to build owner reference"))]
    ObjectMissingMetadataForOwnerRef {
        source: stackable_operator::builder::meta::Error,
    },

    #[snafu(display("failed to transform configs"))]
    ProductConfigTransform {
        source: stackable_operator::product_config_utils::Error,
    },

    #[snafu(display("failed to format runtime properties"))]
    FailedToWriteJavaProperties { source: PropertiesWriterError },

    #[snafu(display("failed to parse role: {source}"))]
    FailedToParseRole { source: strum::ParseError },

    #[snafu(display("internal operator failure: {source}"))]
    InternalOperatorFailure { source: crate::crd::Error },

    #[snafu(display("no coordinator pods found for discovery"))]
    MissingCoordinatorPods,

    #[snafu(display("invalid OpaConfig"))]
    InvalidOpaConfig {
        source: stackable_operator::commons::opa::Error,
    },

    #[snafu(display("failed to get associated TrinoCatalogs"))]
    GetCatalogs {
        source: stackable_operator::client::Error,
    },

    #[snafu(display("failed to parse {catalog}"))]
    ParseCatalog {
        source: FromTrinoCatalogError,
        catalog: ObjectRef<catalog::v1alpha1::TrinoCatalog>,
    },

    #[snafu(display("illegal container name: [{container_name}]"))]
    IllegalContainerName {
        source: stackable_operator::builder::pod::container::Error,
        container_name: String,
    },

    #[snafu(display("failed to retrieve secret for internal communications"))]
    FailedToRetrieveInternalSecret {
        source: stackable_operator::client::Error,
    },

    #[snafu(display("failed to resolve and merge config for role and role group"))]
    FailedToResolveConfig { source: crate::crd::Error },

    #[snafu(display("vector agent is enabled but vector aggregator ConfigMap is missing"))]
    VectorAggregatorConfigMapMissing,

    #[snafu(display("failed to build vector container"))]
    BuildVectorContainer { source: LoggingError },

    #[snafu(display("failed to add the logging configuration to the ConfigMap [{cm_name}]"))]
    InvalidLoggingConfig {
        source: crate::product_logging::Error,
        cm_name: String,
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

    #[snafu(display("failed to retrieve AuthenticationClass"))]
    AuthenticationClassRetrieval {
        source: crate::crd::authentication::Error,
    },

    #[snafu(display("unsupported Trino authentication"))]
    UnsupportedAuthenticationConfig {
        source: crate::authentication::Error,
    },

    #[snafu(display("invalid Trino authentication"))]
    InvalidAuthenticationConfig {
        source: crate::authentication::Error,
    },

    #[snafu(display("failed to serialize [{JVM_SECURITY_PROPERTIES}] for {}", rolegroup))]
    JvmSecurityProperties {
        source: PropertiesWriterError,
        rolegroup: String,
    },

    #[snafu(display("failed to create PodDisruptionBudget"))]
    FailedToCreatePdb {
        source: crate::operations::pdb::Error,
    },

    #[snafu(display("failed to configure graceful shutdown"))]
    GracefulShutdown {
        source: crate::operations::graceful_shutdown::Error,
    },

    #[snafu(display("failed to configure fault tolerant execution"))]
    FaultTolerantExecution {
        source: fault_tolerant_execution::Error,
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

    #[snafu(display("failed to build JVM config"))]
    FailedToCreateJvmConfig { source: crate::config::jvm::Error },

    #[snafu(display("failed to add needed volume"))]
    AddVolume { source: builder::pod::Error },

    #[snafu(display("failed to add needed volumeMount"))]
    AddVolumeMount {
        source: builder::pod::container::Error,
    },

    #[snafu(display("invalid TrinoCluster object"))]
    InvalidTrinoCluster {
        source: error_boundary::InvalidObject,
    },

    #[snafu(display("failed to read role"))]
    ReadRole { source: crate::crd::Error },

    #[snafu(display("unable to parse Trino version: {product_version:?}"))]
    ParseTrinoVersion {
        source: ParseIntError,
        product_version: String,
    },

    #[snafu(display("failed to apply group listener"))]
    ApplyGroupListener {
        source: stackable_operator::cluster_resources::Error,
    },

    #[snafu(display("failed to configure listener"))]
    ListenerConfiguration { source: crate::listener::Error },

    #[snafu(display("failed to configure service"))]
    ServiceConfiguration { source: crate::service::Error },

    #[snafu(display("failed to resolve product image"))]
    ResolveProductImage {
        source: product_image_selection::Error,
    },

    #[snafu(display("failed to resolve client protocol configuration"))]
    ClientProtocolConfiguration { source: client_protocol::Error },

    #[snafu(display(
        "client spooling protocol is not supported for Trino version {product_version}"
    ))]
    ClientSpoolingProtocolTrinoVersion { product_version: String },
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

    let namespace = trino.namespace_r().context(MissingTrinoNamespaceSnafu {
        name: trino.name_any(),
    })?;

    let resolved_product_image = trino
        .spec
        .image
        .resolve(DOCKER_IMAGE_BASE_NAME, crate::built_info::PKG_VERSION)
        .context(ResolveProductImageSnafu)?;

    let resolved_authentication_classes =
        resolve_authentication_classes(client, trino.get_authentication())
            .await
            .context(AuthenticationClassRetrievalSnafu)?;
    let trino_authentication_config = TrinoAuthenticationConfig::new(
        &resolved_product_image,
        TrinoAuthenticationTypes::try_from(resolved_authentication_classes)
            .context(UnsupportedAuthenticationConfigSnafu)?,
    )
    .context(InvalidAuthenticationConfigSnafu)?;

    let catalog_definitions = client
        .list_with_label_selector::<catalog::v1alpha1::TrinoCatalog>(
            trino
                .metadata
                .namespace
                .as_deref()
                .context(ObjectHasNoNamespaceSnafu)?,
            &trino.spec.cluster_config.catalog_label_selector,
        )
        .await
        .context(GetCatalogsSnafu)?;
    let mut catalogs = vec![];
    let product_version = trino.spec.image.product_version();
    let product_version =
        u16::from_str(product_version).context(ParseTrinoVersionSnafu { product_version })?;
    for catalog in &catalog_definitions {
        let catalog_ref = ObjectRef::from_obj(catalog);
        let catalog_config = CatalogConfig::from_catalog(catalog, client, product_version)
            .await
            .context(ParseCatalogSnafu {
                catalog: catalog_ref,
            })?;

        catalogs.push(catalog_config);
    }

    // Resolve fault tolerant execution configuration with S3 connections if needed
    let resolved_fte_config = match trino.spec.cluster_config.fault_tolerant_execution.as_ref() {
        Some(fte_config) => Some(
            fault_tolerant_execution::ResolvedFaultTolerantExecutionConfig::from_config(
                fte_config,
                Some(client),
                &namespace,
            )
            .await
            .context(FaultTolerantExecutionSnafu)?,
        ),
        None => None,
    };

    // Resolve client spooling protocol configuration with S3 connections if needed
    let resolved_client_protocol_config = match trino.spec.cluster_config.client_protocol.as_ref() {
        Some(spooling_config) => Some(
            client_protocol::ResolvedClientProtocolConfig::from_config(
                spooling_config,
                Some(client),
                &namespace,
            )
            .await
            .context(ClientProtocolConfigurationSnafu)?,
        ),
        None => None,
    };
    if resolved_client_protocol_config.is_some()
        && resolved_product_image.product_version.starts_with("45")
    {
        return Err(Error::ClientSpoolingProtocolTrinoVersion {
            product_version: resolved_product_image.product_version,
        });
    }

    let validated_config = validated_product_config(
        trino,
        // The Trino version is a single number like 396.
        // The product config expects semver formatted version strings.
        // That is why we just add minor and patch version 0 here.
        &format!("{}.0.0", resolved_product_image.product_version),
        &ctx.product_config,
    )?;

    let mut cluster_resources = ClusterResources::new(
        APP_NAME,
        OPERATOR_NAME,
        CONTROLLER_NAME,
        &trino.object_ref(&()),
        ClusterResourceApplyStrategy::from(&trino.spec.cluster_operation),
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

    let trino_opa_config = match trino.get_opa_config() {
        Some(opa_config) => Some(
            TrinoOpaConfig::from_opa_config(client, trino, opa_config)
                .await
                .context(InvalidOpaConfigSnafu)?,
        ),
        None => None,
    };

    create_random_secret(
        &shared_internal_secret_name(trino),
        ENV_INTERNAL_SECRET,
        512,
        trino,
        client,
    )
    .await?;

    // This secret is created even if spooling is not configured.
    // Trino currently requires the secret to be exactly 256 bits long.
    create_random_secret(
        &shared_spooling_secret_name(trino),
        ENV_SPOOLING_SECRET,
        32,
        trino,
        client,
    )
    .await?;

    let mut sts_cond_builder = StatefulSetConditionBuilder::default();

    for (trino_role_str, role_config) in validated_config {
        let trino_role = TrinoRole::from_str(&trino_role_str).context(FailedToParseRoleSnafu)?;
        let role = trino.role(&trino_role).context(ReadRoleSnafu)?;
        for (role_group, config) in role_config {
            let role_group_ref = trino_role.rolegroup_ref(trino, &role_group);

            let merged_config = trino
                .merged_config(&trino_role, &role_group_ref, &catalog_definitions)
                .context(FailedToResolveConfigSnafu)?;

            let role_group_service_recommended_labels = build_recommended_labels(
                trino,
                &resolved_product_image.app_version_label_value,
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
                role_group_service_recommended_labels.clone(),
                role_group_service_selector.clone().into(),
            )
            .context(ServiceConfigurationSnafu)?;

            let rg_metrics_service = build_rolegroup_metrics_service(
                trino,
                &role_group_ref,
                role_group_service_recommended_labels,
                role_group_service_selector.into(),
            )
            .context(ServiceConfigurationSnafu)?;

            let rg_configmap = build_rolegroup_config_map(
                trino,
                &resolved_product_image,
                &role,
                &trino_role,
                &role_group_ref,
                &config,
                &merged_config,
                &trino_authentication_config,
                &trino_opa_config,
                &client.kubernetes_cluster_info,
                &resolved_fte_config,
                &resolved_client_protocol_config,
            )?;
            let rg_catalog_configmap = build_rolegroup_catalog_config_map(
                trino,
                &resolved_product_image,
                &role_group_ref,
                &catalogs,
            )?;
            let rg_stateful_set = build_rolegroup_statefulset(
                trino,
                &trino_role,
                &resolved_product_image,
                &role_group_ref,
                &config,
                &merged_config,
                &trino_authentication_config,
                &catalogs,
                &rbac_sa.name_any(),
                &resolved_fte_config,
                &resolved_client_protocol_config,
                &trino_opa_config,
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
            if let Some(listener_group_name) = group_listener_name(trino, &trino_role) {
                let role_group_listener = build_group_listener(
                    trino,
                    build_recommended_labels(
                        trino,
                        &resolved_product_image.app_version_label_value,
                        &trino_role_str,
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
        }

        let role_config = trino.generic_role_config(&trino_role);
        if let Some(GenericRoleConfig {
            pod_disruption_budget: pdb,
        }) = role_config
        {
            add_pdbs(pdb, trino, &trino_role, client, &mut cluster_resources)
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

/// The rolegroup [`ConfigMap`] configures the rolegroup based on the configuration given by the administrator
#[allow(clippy::too_many_arguments)]
fn build_rolegroup_config_map(
    trino: &v1alpha1::TrinoCluster,
    resolved_product_image: &ResolvedProductImage,
    role: &Role<v1alpha1::TrinoConfigFragment, GenericRoleConfig, JavaCommonConfig>,
    trino_role: &TrinoRole,
    rolegroup_ref: &RoleGroupRef<v1alpha1::TrinoCluster>,
    config: &HashMap<PropertyNameKind, BTreeMap<String, String>>,
    merged_config: &v1alpha1::TrinoConfig,
    trino_authentication_config: &TrinoAuthenticationConfig,
    trino_opa_config: &Option<TrinoOpaConfig>,
    cluster_info: &KubernetesClusterInfo,
    resolved_fte_config: &Option<fault_tolerant_execution::ResolvedFaultTolerantExecutionConfig>,
    resolved_spooling_config: &Option<client_protocol::ResolvedClientProtocolConfig>,
) -> Result<ConfigMap> {
    let mut cm_conf_data = BTreeMap::new();

    let product_version = &resolved_product_image.product_version;
    let product_version =
        u16::from_str(product_version).context(ParseTrinoVersionSnafu { product_version })?;
    let jvm_config = config::jvm::jvm_config(
        product_version,
        merged_config,
        role,
        &rolegroup_ref.role_group,
    )
    .context(FailedToCreateJvmConfigSnafu)?;

    // TODO: we support only one coordinator for now
    let coordinator_ref: TrinoPodRef = trino
        .coordinator_pods()
        .context(InternalOperatorFailureSnafu)?
        .next()
        .context(MissingCoordinatorPodsSnafu)?;

    // Add additional config files for authentication
    cm_conf_data.extend(trino_authentication_config.config_files(trino_role));

    for (property_name_kind, config) in config {
        // We used this temporary map to add all dynamically resolved (e.g. discovery config maps)
        // properties. This will be extended with the merged role group properties (transformed_config)
        // to respect all possible override settings.
        let mut dynamic_resolved_config = BTreeMap::<String, Option<String>>::new();

        let transformed_config: BTreeMap<String, Option<String>> = config
            .iter()
            .map(|(k, v)| (k.clone(), Some(v.clone())))
            .collect();

        match property_name_kind {
            PropertyNameKind::File(file_name) if file_name == CONFIG_PROPERTIES => {
                // Add authentication properties (only required for the Coordinator)
                dynamic_resolved_config.extend(
                    trino_authentication_config
                        .config_properties(trino_role)
                        .into_iter()
                        .map(|(k, v)| (k, Some(v)))
                        .collect::<BTreeMap<String, Option<String>>>(),
                );

                let protocol = if trino.get_internal_tls().is_some() {
                    TrinoDiscoveryProtocol::Https
                } else {
                    TrinoDiscoveryProtocol::Http
                };

                let discovery = TrinoDiscovery::new(&coordinator_ref, protocol);
                dynamic_resolved_config.insert(
                    DISCOVERY_URI.to_string(),
                    Some(discovery.discovery_uri(cluster_info)),
                );

                dynamic_resolved_config
                    .extend(graceful_shutdown_config_properties(trino, trino_role));

                // Add fault tolerant execution properties from resolved configuration
                if let Some(resolved_fte) = resolved_fte_config {
                    dynamic_resolved_config.extend(
                        resolved_fte
                            .config_properties
                            .iter()
                            .map(|(k, v)| (k.clone(), Some(v.clone()))),
                    );
                }

                // Add spooling properties from resolved configuration
                if let Some(resolved_spooling) = resolved_spooling_config {
                    dynamic_resolved_config.extend(
                        resolved_spooling
                            .config_properties
                            .iter()
                            .map(|(k, v)| (k.clone(), Some(v.clone()))),
                    );
                }

                // Add static properties and overrides
                dynamic_resolved_config.extend(transformed_config);

                let config_properties = product_config::writer::to_java_properties_string(
                    dynamic_resolved_config.iter(),
                )
                .context(FailedToWriteJavaPropertiesSnafu)?;

                cm_conf_data.insert(file_name.to_string(), config_properties);
            }

            PropertyNameKind::File(file_name) if file_name == NODE_PROPERTIES => {
                // Add static properties and overrides
                dynamic_resolved_config.extend(transformed_config);

                let node_properties = product_config::writer::to_java_properties_string(
                    dynamic_resolved_config.iter(),
                )
                .context(FailedToWriteJavaPropertiesSnafu)?;

                cm_conf_data.insert(file_name.to_string(), node_properties);
            }
            PropertyNameKind::File(file_name) if file_name == LOG_PROPERTIES => {
                // No overrides required here, all settings can be set via logging options
                if let Some(log_properties) = get_log_properties(&merged_config.logging) {
                    cm_conf_data.insert(file_name.to_string(), log_properties);
                }

                if let Some(vector_toml) = get_vector_toml(rolegroup_ref, &merged_config.logging)
                    .context(InvalidLoggingConfigSnafu {
                        cm_name: rolegroup_ref.object_name(),
                    })?
                {
                    cm_conf_data.insert(
                        product_logging::framework::VECTOR_CONFIG_FILE.to_string(),
                        vector_toml,
                    );
                }
            }
            PropertyNameKind::File(file_name) if file_name == ACCESS_CONTROL_PROPERTIES => {
                if let Some(trino_opa_config) = trino_opa_config {
                    dynamic_resolved_config.extend(trino_opa_config.as_config());
                }

                // Add static properties and overrides
                dynamic_resolved_config.extend(transformed_config);

                if !dynamic_resolved_config.is_empty() {
                    let access_control_properties =
                        product_config::writer::to_java_properties_string(
                            dynamic_resolved_config.iter(),
                        )
                        .context(FailedToWriteJavaPropertiesSnafu)?;

                    cm_conf_data.insert(file_name.to_string(), access_control_properties);
                }
            }
            PropertyNameKind::File(file_name) if file_name == JVM_CONFIG => {}
            PropertyNameKind::File(file_name) if file_name == SPOOLING_MANAGER_PROPERTIES => {
                // Add automatic properties for the spooling protocol
                if let Some(spooling_config) = resolved_spooling_config {
                    dynamic_resolved_config = spooling_config
                        .spooling_manager_properties
                        .iter()
                        .map(|(k, v)| (k.clone(), Some(v.clone())))
                        .collect();
                }

                // Override automatic properties with user provided configuration for the spooling protocol
                dynamic_resolved_config.extend(transformed_config);

                if !dynamic_resolved_config.is_empty() {
                    cm_conf_data.insert(
                        file_name.to_string(),
                        to_java_properties_string(dynamic_resolved_config.iter())
                            .with_context(|_| FailedToWriteJavaPropertiesSnafu)?,
                    );
                }
            }
            PropertyNameKind::File(file_name) if file_name == EXCHANGE_MANAGER_PROPERTIES => {
                // Add exchange manager properties from resolved fault tolerant execution configuration
                if let Some(resolved_fte) = resolved_fte_config {
                    dynamic_resolved_config = resolved_fte
                        .exchange_manager_properties
                        .iter()
                        .map(|(k, v)| (k.clone(), Some(v.clone())))
                        .collect();
                }

                // Override automatic properties with user provided configuration for the spooling protocol
                dynamic_resolved_config.extend(transformed_config);

                if !dynamic_resolved_config.is_empty() {
                    cm_conf_data.insert(
                        file_name.to_string(),
                        to_java_properties_string(dynamic_resolved_config.iter())
                            .with_context(|_| FailedToWriteJavaPropertiesSnafu)?,
                    );
                }
            }
            _ => {}
        }
    }

    cm_conf_data.insert(JVM_CONFIG.to_string(), jvm_config.to_string());

    let jvm_sec_props: BTreeMap<String, Option<String>> = config
        .get(&PropertyNameKind::File(JVM_SECURITY_PROPERTIES.to_string()))
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|(k, v)| (k, Some(v)))
        .collect();

    cm_conf_data.insert(
        JVM_SECURITY_PROPERTIES.to_string(),
        to_java_properties_string(jvm_sec_props.iter()).with_context(|_| {
            JvmSecurityPropertiesSnafu {
                rolegroup: rolegroup_ref.role_group.clone(),
            }
        })?,
    );

    ConfigMapBuilder::new()
        .metadata(
            ObjectMetaBuilder::new()
                .name_and_namespace(trino)
                .name(rolegroup_ref.object_name())
                .ownerreference_from_resource(trino, None, Some(true))
                .context(ObjectMissingMetadataForOwnerRefSnafu)?
                .with_recommended_labels(build_recommended_labels(
                    trino,
                    &resolved_product_image.app_version_label_value,
                    &rolegroup_ref.role,
                    &rolegroup_ref.role_group,
                ))
                .context(MetadataBuildSnafu)?
                .build(),
        )
        .data(cm_conf_data)
        .build()
        .with_context(|_| BuildRoleGroupConfigSnafu {
            rolegroup: rolegroup_ref.clone(),
        })
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
                .with_recommended_labels(build_recommended_labels(
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
                    let catalog_props = catalog
                        .properties
                        .iter()
                        .map(|(k, v)| (k.to_string(), Some(v.to_string())))
                        .collect::<Vec<_>>();
                    Ok((
                        format!("{}.properties", catalog.name),
                        // false positive https://github.com/rust-lang/rust-clippy/issues/9280
                        // we need the tuple (&String, &Option<String>) which the extra map is doing.
                        // Removing the map changes the type to &(String, Option<String>)
                        #[allow(clippy::map_identity)]
                        product_config::writer::to_java_properties_string(
                            catalog_props.iter().map(|(k, v)| (k, v)),
                        )
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
    config: &HashMap<PropertyNameKind, BTreeMap<String, String>>,
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
    add_graceful_shutdown_config(
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
    env.extend(
        config
            .get(&PropertyNameKind::Env)
            .into_iter()
            .flatten()
            .map(|(k, v)| EnvVar {
                name: k.clone(),
                value: Some(v.clone()),
                ..EnvVar::default()
            }),
    );

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
    if trino_opa_config
        .as_ref()
        .and_then(|c| c.tls_secret_class.as_ref())
        .is_some()
    {
        prepare_args.extend(command::add_cert_to_truststore(
            &format!("/stackable/secrets/{OPA_TLS_VOLUME_NAME}/ca.crt"),
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
        let unversioned_recommended_labels = Labels::recommended(build_recommended_labels(
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
        .with_recommended_labels(build_recommended_labels(
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

    Ok(StatefulSet {
        metadata: ObjectMetaBuilder::new()
            .name_and_namespace(trino)
            .name(role_group_ref.object_name())
            .ownerreference_from_resource(trino, None, Some(true))
            .context(ObjectMissingMetadataForOwnerRefSnafu)?
            .with_recommended_labels(build_recommended_labels(
                trino,
                &resolved_product_image.app_version_label_value,
                &role_group_ref.role,
                &role_group_ref.role_group,
            ))
            .context(MetadataBuildSnafu)?
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

/// Defines all required roles and their required configuration.
///
/// The roles and their configs are then validated and complemented by the product config.
///
/// # Arguments
/// * `resource`        - The TrinoCluster containing the role definitions.
/// * `version`         - The TrinoCluster version.
/// * `product_config`  - The product config to validate and complement the user config.
///
fn validated_product_config(
    trino: &v1alpha1::TrinoCluster,
    version: &str,
    product_config: &ProductConfigManager,
) -> Result<ValidatedRoleConfigByPropertyKind, Error> {
    let mut roles = HashMap::new();

    let config_files = vec![
        PropertyNameKind::Env,
        PropertyNameKind::File(CONFIG_PROPERTIES.to_string()),
        PropertyNameKind::File(NODE_PROPERTIES.to_string()),
        PropertyNameKind::File(JVM_CONFIG.to_string()),
        PropertyNameKind::File(LOG_PROPERTIES.to_string()),
        PropertyNameKind::File(JVM_SECURITY_PROPERTIES.to_string()),
        PropertyNameKind::File(ACCESS_CONTROL_PROPERTIES.to_string()),
        PropertyNameKind::File(SPOOLING_MANAGER_PROPERTIES.to_string()),
        PropertyNameKind::File(EXCHANGE_MANAGER_PROPERTIES.to_string()),
    ];

    let coordinator_role = TrinoRole::Coordinator;
    roles.insert(
        coordinator_role.to_string(),
        (
            config_files.clone(),
            trino
                .role(&coordinator_role)
                .with_context(|_| MissingTrinoRoleSnafu {
                    role: coordinator_role.to_string(),
                })?,
        ),
    );

    let worker_role = TrinoRole::Worker;
    roles.insert(
        worker_role.to_string(),
        (
            config_files,
            trino
                .role(&worker_role)
                .with_context(|_| MissingTrinoRoleSnafu {
                    role: worker_role.to_string(),
                })?,
        ),
    );

    let role_config =
        transform_all_roles_to_config(trino, roles).context(ProductConfigTransformSnafu)?;

    validate_all_roles_and_groups_config(version, &role_config, product_config, false, false)
        .context(InvalidProductConfigSnafu)
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

async fn create_random_secret(
    secret_name: &str,
    secret_key: &str,
    secret_byte_size: usize,
    trino: &v1alpha1::TrinoCluster,
    client: &Client,
) -> Result<()> {
    let mut internal_secret = BTreeMap::new();
    internal_secret.insert(secret_key.to_string(), get_random_base64(secret_byte_size));

    let secret = Secret {
        immutable: Some(true),
        metadata: ObjectMetaBuilder::new()
            .name(secret_name)
            .namespace_opt(trino.namespace())
            .ownerreference_from_resource(trino, None, Some(true))
            .context(ObjectMissingMetadataForOwnerRefSnafu)?
            .build(),
        string_data: Some(internal_secret),
        ..Secret::default()
    };

    if client
        .get_opt::<Secret>(
            &secret.name_any(),
            secret
                .namespace()
                .as_deref()
                .context(ObjectHasNoNamespaceSnafu)?,
        )
        .await
        .context(FailedToRetrieveInternalSecretSnafu)?
        .is_none()
    {
        client
            .apply_patch(CONTROLLER_NAME, &secret, &secret)
            .await
            .context(ApplyInternalSecretSnafu)?;
    }

    Ok(())
}

fn shared_internal_secret_name(trino: &v1alpha1::TrinoCluster) -> String {
    format!("{}-internal-secret", trino.name_any())
}

fn shared_spooling_secret_name(trino: &v1alpha1::TrinoCluster) -> String {
    format!("{}-spooling-secret", trino.name_any())
}

// TODO: Maybe switch to something non-openssl.
// See https://github.com/stackabletech/airflow-operator/pull/686#discussion_r2348354468 (which is currently under discussion)
fn get_random_base64(byte_size: usize) -> String {
    let mut buf: Vec<u8> = vec![0; byte_size];
    openssl::rand::rand_bytes(&mut buf).unwrap();
    openssl::base64::encode_block(&buf)
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
    let mut secret_volume_source_builder = SecretOperatorVolumeSourceBuilder::new(tls_secret_class);

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

    if let Some(opa_config) = trino_opa_config {
        if let Some(opa_tls_secret_class) = &opa_config.tls_secret_class {
            let opa_tls_mount_path = format!("/stackable/secrets/{OPA_TLS_VOLUME_NAME}");

            cb_prepare
                .add_volume_mount(OPA_TLS_VOLUME_NAME, &opa_tls_mount_path)
                .context(AddVolumeMountSnafu)?;

            let opa_tls_volume = VolumeBuilder::new(OPA_TLS_VOLUME_NAME)
                .ephemeral(
                    SecretOperatorVolumeSourceBuilder::new(opa_tls_secret_class)
                        .build()
                        .context(TlsCertSecretClassVolumeBuildSnafu)?,
                )
                .build();

            pod_builder
                .add_volume(opa_tls_volume)
                .context(AddVolumeSnafu)?;
        }
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
    use stackable_operator::commons::networking::DomainName;

    use super::*;
    use crate::{
        config::{
            client_protocol::ResolvedClientProtocolConfig,
            fault_tolerant_execution::ResolvedFaultTolerantExecutionConfig,
        },
        crd::v1alpha1::TrinoCluster,
    };

    #[tokio::test]
    async fn test_config_overrides() {
        let trino_yaml = r#"
        apiVersion: trino.stackable.tech/v1alpha1
        kind: TrinoCluster
        metadata:
          name: simple-trino
        spec:
          image:
            productVersion: "477"
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
            productVersion: "477"
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

    async fn build_config_map(trino_yaml: &str) -> ConfigMap {
        let deserializer = serde_yaml::Deserializer::from_str(trino_yaml);
        let mut trino: TrinoCluster =
            serde_yaml::with::singleton_map_recursive::deserialize(deserializer)
                .expect("invalid test input");
        trino.metadata.namespace = Some("default".to_owned());
        trino.metadata.uid = Some("42".to_owned());
        let cluster_info = KubernetesClusterInfo {
            cluster_domain: DomainName::try_from("cluster.local").unwrap(),
        };
        let resolved_product_image = trino
            .spec
            .image
            .resolve(DOCKER_IMAGE_BASE_NAME, "0.0.0-dev")
            .expect("test resolved product image is always valid");

        let config_files = vec![
            PropertyNameKind::File(CONFIG_PROPERTIES.to_string()),
            PropertyNameKind::File(NODE_PROPERTIES.to_string()),
            PropertyNameKind::File(JVM_CONFIG.to_string()),
            PropertyNameKind::File(LOG_PROPERTIES.to_string()),
            PropertyNameKind::File(JVM_SECURITY_PROPERTIES.to_string()),
            PropertyNameKind::File(ACCESS_CONTROL_PROPERTIES.to_string()),
            PropertyNameKind::File(SPOOLING_MANAGER_PROPERTIES.to_string()),
            PropertyNameKind::File(EXCHANGE_MANAGER_PROPERTIES.to_string()),
        ];
        let validated_config = validate_all_roles_and_groups_config(
            // The Trino version is a single number like 396.
            // The product config expects semver formatted version strings.
            // That is why we just add minor and patch version 0 here.
            &format!("{}.0.0", resolved_product_image.product_version),
            &transform_all_roles_to_config(
                &trino,
                [
                    (
                        TrinoRole::Coordinator.to_string(),
                        (
                            config_files.clone(),
                            trino.role(&TrinoRole::Coordinator).unwrap(),
                        ),
                    ),
                    (
                        TrinoRole::Worker.to_string(),
                        (config_files, trino.role(&TrinoRole::Worker).unwrap()),
                    ),
                ]
                .into(),
            )
            .unwrap(),
            // Using this instead of ProductConfigManager::from_yaml_file, as that did not find the file
            &ProductConfigManager::from_str(include_str!(
                "../../../deploy/config-spec/properties.yaml"
            ))
            .unwrap(),
            false,
            false,
        )
        .unwrap();

        let trino_role = TrinoRole::Coordinator;
        let role = trino.role(&trino_role).unwrap();
        let rolegroup_ref = RoleGroupRef {
            cluster: ObjectRef::from_obj(&trino),
            role: trino_role.to_string(),
            role_group: "default".to_string(),
        };
        let trino_authentication_config = TrinoAuthenticationConfig::new(
            &resolved_product_image,
            TrinoAuthenticationTypes::try_from(Vec::new()).unwrap(),
        )
        .unwrap();
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
            column_masking_connection_string: Some(
                "http://simple-opa.default.svc.cluster.local:8081/v1/data/my-product/columnMask"
                    .to_string(),
            ),
            allow_permission_management_operations: true,
            tls_secret_class: None,
        });
        let resolved_fte_config = match &trino.spec.cluster_config.fault_tolerant_execution {
            Some(fault_tolerant_execution) => Some(
                ResolvedFaultTolerantExecutionConfig::from_config(
                    fault_tolerant_execution,
                    None,
                    &trino.namespace().unwrap(),
                )
                .await
                .unwrap(),
            ),
            None => None,
        };
        let resolved_spooling_config = match &trino.spec.cluster_config.client_protocol {
            Some(client_protocol) => Some(
                ResolvedClientProtocolConfig::from_config(
                    client_protocol,
                    None,
                    &trino.namespace().unwrap(),
                )
                .await
                .unwrap(),
            ),
            None => None,
        };
        let merged_config = trino
            .merged_config(&trino_role, &rolegroup_ref, &[])
            .unwrap();

        build_rolegroup_config_map(
            &trino,
            &resolved_product_image,
            &role,
            &trino_role,
            &rolegroup_ref,
            validated_config
                .get("coordinator")
                .unwrap()
                .get("default")
                .unwrap(),
            &merged_config,
            &trino_authentication_config,
            &trino_opa_config,
            &cluster_info,
            &resolved_fte_config,
            &resolved_spooling_config,
        )
        .unwrap()
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
            productVersion: "477"
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
                foo.bar: "false" # overriden by role group below
                opa.allow-permission-management-operations: "false" # override value from config
            roleGroups:
              default:
                configOverrides:
                  access-control.properties:
                    hello-from-role-group: "true" # only defined here at group level
                    foo.bar: "true" # overrides role value
                    opa.policy.batched-uri: "http://simple-opa.default.svc.cluster.local:8081/v1/data/my-product/batch-new" # override value from config
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
        assert!(access_control_config.contains(r#"opa.policy.column-masking-uri=http\://simple-opa.default.svc.cluster.local\:8081/v1/data/my-product/columnMask"#));
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
        spec:
          image:
            productVersion: "477"
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

        let validated_config = validated_product_config(
            &trino,
            "455.0.0",
            &ProductConfigManager::from_yaml_file("../../deploy/config-spec/properties.yaml")
                .unwrap(),
        )
        .unwrap();

        let env = validated_config
            .get(&TrinoRole::Coordinator.to_string())
            .unwrap()
            .get("default")
            .unwrap()
            .get(&PropertyNameKind::Env)
            .unwrap();

        assert_eq!(&"group-value".to_string(), env.get("COMMON_VAR").unwrap());
        assert_eq!(&"group-value".to_string(), env.get("GROUP_VAR").unwrap());
        assert_eq!(&"role-value".to_string(), env.get("ROLE_VAR").unwrap());
    }
}
