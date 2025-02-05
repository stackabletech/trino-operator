//! Ensures that `Pod`s are configured and running for each [`TrinoCluster`]
use std::{
    collections::{BTreeMap, HashMap},
    convert::Infallible,
    ops::Div,
    str::FromStr,
    sync::Arc,
};

use const_format::concatcp;
use product_config::{
    self,
    types::PropertyNameKind,
    writer::{to_java_properties_string, PropertiesWriterError},
    ProductConfigManager,
};
use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::{
    builder::{
        self,
        configmap::ConfigMapBuilder,
        meta::ObjectMetaBuilder,
        pod::{
            container::ContainerBuilder,
            resources::ResourceRequirementsBuilder,
            security::PodSecurityContextBuilder,
            volume::{SecretFormat, SecretOperatorVolumeSourceBuilder, VolumeBuilder},
            PodBuilder,
        },
    },
    client::Client,
    cluster_resources::{ClusterResourceApplyStrategy, ClusterResources},
    commons::{product_image_selection::ResolvedProductImage, rbac::build_rbac_resources},
    k8s_openapi::{
        api::{
            apps::v1::{StatefulSet, StatefulSetSpec},
            core::v1::{
                ConfigMap, ConfigMapVolumeSource, ContainerPort, EnvVar, EnvVarSource, Probe,
                Secret, SecretKeySelector, Service, ServicePort, ServiceSpec, TCPSocketAction,
                Volume,
            },
        },
        apimachinery::pkg::{apis::meta::v1::LabelSelector, util::intstr::IntOrString},
        DeepMerge,
    },
    kube::{
        core::{error_boundary, DeserializeGuard},
        runtime::{controller::Action, reflector::ObjectRef},
        Resource, ResourceExt,
    },
    kvp::{Annotation, Label, Labels, ObjectLabels},
    logging::controller::ReconcilerError,
    memory::{BinaryMultiple, MemoryQuantity},
    product_config_utils::{
        transform_all_roles_to_config, validate_all_roles_and_groups_config,
        ValidatedRoleConfigByPropertyKind,
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
    status::condition::{
        compute_conditions, operations::ClusterOperationsConditionBuilder,
        statefulset::StatefulSetConditionBuilder,
    },
    time::Duration,
    utils::cluster_info::KubernetesClusterInfo,
};
use stackable_trino_crd::{
    authentication::resolve_authentication_classes,
    catalog::TrinoCatalog,
    discovery::{TrinoDiscovery, TrinoDiscoveryProtocol, TrinoPodRef},
    Container, TrinoCluster, TrinoClusterStatus, TrinoConfig, TrinoConfigFragment, TrinoRole,
    ACCESS_CONTROL_PROPERTIES, APP_NAME, CONFIG_DIR_NAME, CONFIG_PROPERTIES, DATA_DIR_NAME,
    DISCOVERY_URI, ENV_INTERNAL_SECRET, HTTPS_PORT, HTTPS_PORT_NAME, HTTP_PORT, HTTP_PORT_NAME,
    JVM_CONFIG, JVM_SECURITY_PROPERTIES, LOG_COMPRESSION, LOG_FORMAT, LOG_MAX_SIZE,
    LOG_MAX_TOTAL_SIZE, LOG_PATH, LOG_PROPERTIES, METRICS_PORT, METRICS_PORT_NAME, NODE_PROPERTIES,
    RW_CONFIG_DIR_NAME, STACKABLE_CLIENT_TLS_DIR, STACKABLE_INTERNAL_TLS_DIR,
    STACKABLE_MOUNT_INTERNAL_TLS_DIR, STACKABLE_MOUNT_SERVER_TLS_DIR, STACKABLE_SERVER_TLS_DIR,
};
use strum::{EnumDiscriminants, IntoStaticStr};

use crate::{
    authentication::{TrinoAuthenticationConfig, TrinoAuthenticationTypes},
    authorization::opa::TrinoOpaConfig,
    catalog::{config::CatalogConfig, FromTrinoCatalogError},
    command, config,
    operations::{
        add_graceful_shutdown_config, graceful_shutdown_config_properties, pdb::add_pdbs,
    },
    product_logging::{get_log_properties, get_vector_toml, resolve_vector_aggregator_address},
};

pub struct Ctx {
    pub client: stackable_operator::client::Client,
    pub product_config: ProductConfigManager,
}

pub const OPERATOR_NAME: &str = "trino.stackable.tech";
pub const CONTROLLER_NAME: &str = "trinocluster";
pub const FULL_CONTROLLER_NAME: &str = concatcp!(CONTROLLER_NAME, '.', OPERATOR_NAME);
pub const TRINO_UID: i64 = 1000;

pub const STACKABLE_LOG_DIR: &str = "/stackable/log";
pub const STACKABLE_LOG_CONFIG_DIR: &str = "/stackable/log_config";

const LOG_FILE_COUNT: u32 = 2;
pub const MAX_TRINO_LOG_FILES_SIZE: MemoryQuantity = MemoryQuantity {
    value: 10.0,
    unit: BinaryMultiple::Mebi,
};
pub const MAX_PREPARE_LOG_FILE_SIZE: MemoryQuantity = MemoryQuantity {
    value: 1.0,
    unit: BinaryMultiple::Mebi,
};

const DOCKER_IMAGE_BASE_NAME: &str = "trino";

#[derive(Snafu, Debug, EnumDiscriminants)]
#[strum_discriminants(derive(IntoStaticStr))]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[snafu(display("missing secret lifetime"))]
    MissingSecretLifetime,

    #[snafu(display("object defines no namespace"))]
    ObjectHasNoNamespace,

    #[snafu(display("object defines no {role:?} role"))]
    MissingTrinoRole { role: String },

    #[snafu(display("failed to create cluster resources"))]
    CreateClusterResources {
        source: stackable_operator::cluster_resources::Error,
    },

    #[snafu(display("failed to delete orphaned resources"))]
    DeleteOrphanedResources {
        source: stackable_operator::cluster_resources::Error,
    },

    #[snafu(display("failed to apply global Service"))]
    ApplyRoleService {
        source: stackable_operator::cluster_resources::Error,
    },

    #[snafu(display("failed to apply Service for {}", rolegroup))]
    ApplyRoleGroupService {
        source: stackable_operator::cluster_resources::Error,
        rolegroup: RoleGroupRef<TrinoCluster>,
    },

    #[snafu(display("failed to build ConfigMap for {}", rolegroup))]
    BuildRoleGroupConfig {
        source: stackable_operator::builder::configmap::Error,
        rolegroup: RoleGroupRef<TrinoCluster>,
    },

    #[snafu(display("failed to apply ConfigMap for {}", rolegroup))]
    ApplyRoleGroupConfig {
        source: stackable_operator::cluster_resources::Error,
        rolegroup: RoleGroupRef<TrinoCluster>,
    },

    #[snafu(display("failed to apply StatefulSet for {}", rolegroup))]
    ApplyRoleGroupStatefulSet {
        source: stackable_operator::cluster_resources::Error,
        rolegroup: RoleGroupRef<TrinoCluster>,
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
    InternalOperatorFailure { source: stackable_trino_crd::Error },

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
        catalog: ObjectRef<TrinoCatalog>,
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
    FailedToResolveConfig { source: stackable_trino_crd::Error },

    #[snafu(display("failed to resolve the Vector aggregator address"))]
    ResolveVectorAggregatorAddress {
        source: crate::product_logging::Error,
    },

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

    #[snafu(display("Failed to retrieve AuthenticationClass"))]
    AuthenticationClassRetrieval {
        source: stackable_trino_crd::authentication::Error,
    },

    #[snafu(display("Unsupported Trino authentication"))]
    UnsupportedAuthenticationConfig {
        source: crate::authentication::Error,
    },

    #[snafu(display("Invalid Trino authentication"))]
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
    ReadRole { source: stackable_trino_crd::Error },

    #[snafu(display("failed to get merged jvmArgumentOverrides"))]
    GetMergedJvmArgumentOverrides {
        source: stackable_operator::role_utils::Error,
    },
}

type Result<T, E = Error> = std::result::Result<T, E>;

impl ReconcilerError for Error {
    fn category(&self) -> &'static str {
        ErrorDiscriminants::from(self).into()
    }
}

pub async fn reconcile_trino(
    trino: Arc<DeserializeGuard<TrinoCluster>>,
    ctx: Arc<Ctx>,
) -> Result<Action> {
    tracing::info!("Starting reconcile");

    let trino = trino
        .0
        .as_ref()
        .map_err(error_boundary::InvalidObject::clone)
        .context(InvalidTrinoClusterSnafu)?;
    let client = &ctx.client;

    let resolved_product_image: ResolvedProductImage = trino
        .spec
        .image
        .resolve(DOCKER_IMAGE_BASE_NAME, crate::built_info::PKG_VERSION);

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
        .list_with_label_selector::<TrinoCatalog>(
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
    for catalog in &catalog_definitions {
        let catalog_ref = ObjectRef::from_obj(catalog);
        let catalog_config =
            CatalogConfig::from_catalog(catalog, client)
                .await
                .context(ParseCatalogSnafu {
                    catalog: catalog_ref,
                })?;

        catalogs.push(catalog_config);
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

    let coordinator_role_service = build_coordinator_role_service(trino, &resolved_product_image)?;

    cluster_resources
        .add(client, coordinator_role_service)
        .await
        .context(ApplyRoleServiceSnafu)?;

    create_shared_internal_secret(trino, client).await?;

    let vector_aggregator_address = resolve_vector_aggregator_address(trino, client)
        .await
        .context(ResolveVectorAggregatorAddressSnafu)?;

    let mut sts_cond_builder = StatefulSetConditionBuilder::default();

    for (trino_role_str, role_config) in validated_config {
        let trino_role = TrinoRole::from_str(&trino_role_str).context(FailedToParseRoleSnafu)?;
        let role: &Role<TrinoConfigFragment, GenericRoleConfig, JavaCommonConfig> =
            trino.role(&trino_role).context(ReadRoleSnafu)?;
        for (role_group, config) in role_config {
            let rolegroup = trino_role.rolegroup_ref(trino, &role_group);

            let merged_config = trino
                .merged_config(&trino_role, &rolegroup, &catalog_definitions)
                .context(FailedToResolveConfigSnafu)?;

            let rg_service = build_rolegroup_service(trino, &resolved_product_image, &rolegroup)?;
            let rg_configmap = build_rolegroup_config_map(
                trino,
                &resolved_product_image,
                role,
                &trino_role,
                &rolegroup,
                &config,
                &merged_config,
                &trino_authentication_config,
                &trino_opa_config,
                vector_aggregator_address.as_deref(),
                &client.kubernetes_cluster_info,
            )?;
            let rg_catalog_configmap = build_rolegroup_catalog_config_map(
                trino,
                &resolved_product_image,
                &rolegroup,
                &catalogs,
            )?;
            let rg_stateful_set = build_rolegroup_statefulset(
                trino,
                &trino_role,
                &resolved_product_image,
                &rolegroup,
                &config,
                &merged_config,
                &trino_authentication_config,
                &catalogs,
                &rbac_sa.name_any(),
            )?;

            cluster_resources
                .add(client, rg_service)
                .await
                .with_context(|_| ApplyRoleGroupServiceSnafu {
                    rolegroup: rolegroup.clone(),
                })?;

            cluster_resources
                .add(client, rg_configmap)
                .await
                .with_context(|_| ApplyRoleGroupConfigSnafu {
                    rolegroup: rolegroup.clone(),
                })?;

            cluster_resources
                .add(client, rg_catalog_configmap)
                .await
                .with_context(|_| ApplyRoleGroupConfigSnafu {
                    rolegroup: rolegroup.clone(),
                })?;

            sts_cond_builder.add(
                cluster_resources
                    .add(client, rg_stateful_set)
                    .await
                    .with_context(|_| ApplyRoleGroupStatefulSetSnafu {
                        rolegroup: rolegroup.clone(),
                    })?,
            );
        }

        let role_config = trino.role_config(&trino_role);
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

    let status = TrinoClusterStatus {
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

/// The coordinator-role service is the primary endpoint that should be used by clients that do not
/// perform internal load balancing, including targets outside of the cluster.
pub fn build_coordinator_role_service(
    trino: &TrinoCluster,
    resolved_product_image: &ResolvedProductImage,
) -> Result<Service> {
    let role = TrinoRole::Coordinator;
    let role_name = role.to_string();
    let role_svc_name = trino
        .role_service_name(&role)
        .context(InternalOperatorFailureSnafu)?;
    Ok(Service {
        metadata: ObjectMetaBuilder::new()
            .name_and_namespace(trino)
            .name(&role_svc_name)
            .ownerreference_from_resource(trino, None, Some(true))
            .context(ObjectMissingMetadataForOwnerRefSnafu)?
            .with_recommended_labels(build_recommended_labels(
                trino,
                &resolved_product_image.app_version_label,
                &role_name,
                "global",
            ))
            .context(MetadataBuildSnafu)?
            .build(),
        spec: Some(ServiceSpec {
            ports: Some(service_ports(trino)),
            selector: Some(
                Labels::role_selector(trino, APP_NAME, &role_name)
                    .context(LabelBuildSnafu)?
                    .into(),
            ),
            type_: Some(trino.spec.cluster_config.listener_class.k8s_service_type()),
            ..ServiceSpec::default()
        }),
        status: None,
    })
}

/// The rolegroup [`ConfigMap`] configures the rolegroup based on the configuration given by the administrator
#[allow(clippy::too_many_arguments)]
fn build_rolegroup_config_map(
    trino: &TrinoCluster,
    resolved_product_image: &ResolvedProductImage,
    role: &Role<TrinoConfigFragment, GenericRoleConfig, JavaCommonConfig>,
    trino_role: &TrinoRole,
    rolegroup_ref: &RoleGroupRef<TrinoCluster>,
    config: &HashMap<PropertyNameKind, BTreeMap<String, String>>,
    merged_config: &TrinoConfig,
    trino_authentication_config: &TrinoAuthenticationConfig,
    trino_opa_config: &Option<TrinoOpaConfig>,
    vector_aggregator_address: Option<&str>,
    cluster_info: &KubernetesClusterInfo,
) -> Result<ConfigMap> {
    let mut cm_conf_data = BTreeMap::new();

    let jvm_config = config::jvm::jvm_config(
        &resolved_product_image.product_version,
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

    // Add additional config files fore authentication
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

                // The log format used by Trino
                dynamic_resolved_config.insert(LOG_FORMAT.to_string(), Some("json".to_string()));
                // The path to the log file used by Trino
                dynamic_resolved_config.insert(
                    LOG_PATH.to_string(),
                    Some(format!(
                        "{STACKABLE_LOG_DIR}/{container}/server.airlift.json",
                        container = Container::Trino
                    )),
                );
                // We do not compress. This will result in LOG_MAX_TOTAL_SIZE / LOG_MAX_SIZE files.
                dynamic_resolved_config
                    .insert(LOG_COMPRESSION.to_string(), Some("none".to_string()));
                // The size of one log file
                dynamic_resolved_config.insert(
                    LOG_MAX_SIZE.to_string(),
                    Some(format!(
                        // Trino uses the unit "MB" for MiB.
                        "{}MB",
                        MAX_TRINO_LOG_FILES_SIZE
                            .scale_to(BinaryMultiple::Mebi)
                            .div(LOG_FILE_COUNT as f32)
                            .ceil()
                            .value,
                    )),
                );
                // The maximum size of all logfiles combined
                dynamic_resolved_config.insert(
                    LOG_MAX_TOTAL_SIZE.to_string(),
                    Some(format!(
                        // Trino uses the unit "MB" for MiB.
                        "{}MB",
                        MAX_TRINO_LOG_FILES_SIZE
                            .scale_to(BinaryMultiple::Mebi)
                            .ceil()
                            .value,
                    )),
                );

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

                if let Some(vector_toml) = get_vector_toml(
                    rolegroup_ref,
                    vector_aggregator_address,
                    &merged_config.logging,
                )
                .context(InvalidLoggingConfigSnafu {
                    cm_name: rolegroup_ref.object_name(),
                })? {
                    cm_conf_data.insert(
                        product_logging::framework::VECTOR_CONFIG_FILE.to_string(),
                        vector_toml,
                    );
                }
            }
            PropertyNameKind::File(file_name) if file_name == JVM_CONFIG => {}
            _ => {}
        }
    }

    if let Some(trino_opa_config) = trino_opa_config {
        let config = trino_opa_config.as_config();
        let config_properties = product_config::writer::to_java_properties_string(config.iter())
            .context(FailedToWriteJavaPropertiesSnafu)?;

        cm_conf_data.insert(ACCESS_CONTROL_PROPERTIES.to_string(), config_properties);
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
                    &resolved_product_image.app_version_label,
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
    trino: &TrinoCluster,
    resolved_product_image: &ResolvedProductImage,
    rolegroup_ref: &RoleGroupRef<TrinoCluster>,
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
                    &resolved_product_image.app_version_label,
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
/// corresponding [`Service`] (from [`build_rolegroup_service`]).
#[allow(clippy::too_many_arguments)]
fn build_rolegroup_statefulset(
    trino: &TrinoCluster,
    trino_role: &TrinoRole,
    resolved_product_image: &ResolvedProductImage,
    rolegroup_ref: &RoleGroupRef<TrinoCluster>,
    config: &HashMap<PropertyNameKind, BTreeMap<String, String>>,
    merged_config: &TrinoConfig,
    trino_authentication_config: &TrinoAuthenticationConfig,
    catalogs: &[CatalogConfig],
    sa_name: &str,
) -> Result<StatefulSet> {
    let role = trino
        .role(trino_role)
        .context(InternalOperatorFailureSnafu)?;
    let rolegroup = trino
        .rolegroup(rolegroup_ref)
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

    let secret_name = build_shared_internal_secret_name(trino);
    env.push(env_var_from_secret(&secret_name, None, ENV_INTERNAL_SECRET));

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
        &mut pod_builder,
        &mut cb_prepare,
        &mut cb_trino,
        catalogs,
        &requested_secret_lifetime,
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
    ));

    prepare_args
        .extend(trino_authentication_config.commands(&TrinoRole::Coordinator, &Container::Prepare));

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
        .add_volume_mount("data", DATA_DIR_NAME)
        .context(AddVolumeMountSnafu)?
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

    let container_trino = cb_trino
        .image_from_product_image(resolved_product_image)
        .command(vec![
            "/bin/bash".to_string(),
            "-x".to_string(),
            "-euo".to_string(),
            "pipefail".to_string(),
            "-c".to_string(),
        ])
        .args(vec![command::container_trino_args(
            trino_authentication_config,
            catalogs,
        )
        .join("\n")])
        .add_env_vars(env)
        .add_volume_mount("data", DATA_DIR_NAME)
        .context(AddVolumeMountSnafu)?
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
                    name: rolegroup_ref.object_name(),
                    ..ConfigMapVolumeSource::default()
                }),
                ..Volume::default()
            })
            .context(AddVolumeSnafu)?;
    }

    if merged_config.logging.enable_vector_agent {
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
            )
            .context(BuildVectorContainerSnafu)?,
        );
    }

    let metadata = ObjectMetaBuilder::new()
        .with_recommended_labels(build_recommended_labels(
            trino,
            &resolved_product_image.app_version_label,
            &rolegroup_ref.role,
            &rolegroup_ref.role_group,
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
                name: rolegroup_ref.object_name(),
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
                name: format!("{}-catalog", rolegroup_ref.object_name()),
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
        .security_context(
            PodSecurityContextBuilder::new()
                .run_as_user(TRINO_UID)
                .run_as_group(0)
                .fs_group(1000)
                .build(),
        );

    let mut pod_template = pod_builder.build_template();
    pod_template.merge_from(role.config.pod_overrides.clone());
    pod_template.merge_from(rolegroup.config.pod_overrides.clone());

    Ok(StatefulSet {
        metadata: ObjectMetaBuilder::new()
            .name_and_namespace(trino)
            .name(rolegroup_ref.object_name())
            .ownerreference_from_resource(trino, None, Some(true))
            .context(ObjectMissingMetadataForOwnerRefSnafu)?
            .with_recommended_labels(build_recommended_labels(
                trino,
                &resolved_product_image.app_version_label,
                &rolegroup_ref.role,
                &rolegroup_ref.role_group,
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
                        &rolegroup_ref.role,
                        &rolegroup_ref.role_group,
                    )
                    .context(LabelBuildSnafu)?
                    .into(),
                ),
                ..LabelSelector::default()
            },
            service_name: rolegroup_ref.object_name(),
            template: pod_template,
            volume_claim_templates: Some(vec![merged_config
                .resources
                .storage
                .data
                .build_pvc("data", Some(vec!["ReadWriteOnce"]))]),
            ..StatefulSetSpec::default()
        }),
        status: None,
    })
}

/// The rolegroup [`Service`] is a headless service that allows direct access to the instances of a certain rolegroup
///
/// This is mostly useful for internal communication between peers, or for clients that perform client-side load balancing.
fn build_rolegroup_service(
    trino: &TrinoCluster,
    resolved_product_image: &ResolvedProductImage,
    rolegroup_ref: &RoleGroupRef<TrinoCluster>,
) -> Result<Service> {
    Ok(Service {
        metadata: ObjectMetaBuilder::new()
            .name_and_namespace(trino)
            .name(rolegroup_ref.object_name())
            .ownerreference_from_resource(trino, None, Some(true))
            .context(ObjectMissingMetadataForOwnerRefSnafu)?
            .with_recommended_labels(build_recommended_labels(
                trino,
                &resolved_product_image.app_version_label,
                &rolegroup_ref.role,
                &rolegroup_ref.role_group,
            ))
            .context(MetadataBuildSnafu)?
            .with_label(Label::try_from(("prometheus.io/scrape", "true")).context(LabelBuildSnafu)?)
            .build(),
        spec: Some(ServiceSpec {
            // Internal communication does not need to be exposed
            type_: Some("ClusterIP".to_string()),
            cluster_ip: Some("None".to_string()),
            ports: Some(service_ports(trino)),
            selector: Some(
                Labels::role_group_selector(
                    trino,
                    APP_NAME,
                    &rolegroup_ref.role,
                    &rolegroup_ref.role_group,
                )
                .context(LabelBuildSnafu)?
                .into(),
            ),
            publish_not_ready_addresses: Some(true),
            ..ServiceSpec::default()
        }),
        status: None,
    })
}

pub fn error_policy(
    _obj: Arc<DeserializeGuard<TrinoCluster>>,
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
    trino: &TrinoCluster,
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
    ];

    roles.insert(
        TrinoRole::Coordinator.to_string(),
        (
            config_files.clone(),
            trino
                .spec
                .coordinators
                .clone()
                .with_context(|| MissingTrinoRoleSnafu {
                    role: TrinoRole::Coordinator.to_string(),
                })?,
        ),
    );

    roles.insert(
        TrinoRole::Worker.to_string(),
        (
            config_files,
            trino
                .spec
                .workers
                .clone()
                .with_context(|| MissingTrinoRoleSnafu {
                    role: TrinoRole::Worker.to_string(),
                })?,
        ),
    );

    let role_config =
        transform_all_roles_to_config(trino, roles).context(ProductConfigTransformSnafu)?;

    validate_all_roles_and_groups_config(version, &role_config, product_config, false, false)
        .context(InvalidProductConfigSnafu)
}

fn build_recommended_labels<'a>(
    owner: &'a TrinoCluster,
    app_version: &'a str,
    role: &'a str,
    role_group: &'a str,
) -> ObjectLabels<'a, TrinoCluster> {
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

async fn create_shared_internal_secret(trino: &TrinoCluster, client: &Client) -> Result<()> {
    let secret = build_shared_internal_secret(trino)?;
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

fn build_shared_internal_secret(trino: &TrinoCluster) -> Result<Secret> {
    let mut internal_secret = BTreeMap::new();
    internal_secret.insert(ENV_INTERNAL_SECRET.to_string(), get_random_base64());

    Ok(Secret {
        immutable: Some(true),
        metadata: ObjectMetaBuilder::new()
            .name(build_shared_internal_secret_name(trino))
            .namespace_opt(trino.namespace())
            .ownerreference_from_resource(trino, None, Some(true))
            .context(ObjectMissingMetadataForOwnerRefSnafu)?
            .build(),
        string_data: Some(internal_secret),
        ..Secret::default()
    })
}

fn build_shared_internal_secret_name(trino: &TrinoCluster) -> String {
    format!("{}-internal-secret", trino.name_any())
}

fn get_random_base64() -> String {
    let mut buf = [0; 512];
    openssl::rand::rand_bytes(&mut buf).unwrap();
    openssl::base64::encode_block(&buf)
}

fn service_ports(trino: &TrinoCluster) -> Vec<ServicePort> {
    let mut ports = vec![ServicePort {
        name: Some(METRICS_PORT_NAME.to_string()),
        port: METRICS_PORT.into(),
        protocol: Some("TCP".to_string()),
        ..ServicePort::default()
    }];

    if trino.expose_http_port() {
        ports.push(ServicePort {
            name: Some(HTTP_PORT_NAME.to_string()),
            port: HTTP_PORT.into(),
            protocol: Some("TCP".to_string()),
            ..ServicePort::default()
        });
    }

    if trino.expose_https_port() {
        ports.push(ServicePort {
            name: Some(HTTPS_PORT_NAME.to_string()),
            port: HTTPS_PORT.into(),
            protocol: Some("TCP".to_string()),
            ..ServicePort::default()
        });
    }

    ports
}

fn container_ports(trino: &TrinoCluster) -> Vec<ContainerPort> {
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

fn readiness_probe(trino: &TrinoCluster) -> Probe {
    let port_name = if trino.expose_https_port() {
        HTTPS_PORT_NAME
    } else {
        HTTP_PORT_NAME
    };

    Probe {
        initial_delay_seconds: Some(10),
        period_seconds: Some(10),
        failure_threshold: Some(5),
        tcp_socket: Some(TCPSocketAction {
            port: IntOrString::String(port_name.to_string()),
            ..TCPSocketAction::default()
        }),
        ..Probe::default()
    }
}

fn liveness_probe(trino: &TrinoCluster) -> Probe {
    let port_name = if trino.expose_https_port() {
        HTTPS_PORT_NAME
    } else {
        HTTP_PORT_NAME
    };

    Probe {
        initial_delay_seconds: Some(30),
        period_seconds: Some(10),
        tcp_socket: Some(TCPSocketAction {
            port: IntOrString::String(port_name.to_string()),
            ..TCPSocketAction::default()
        }),
        ..Probe::default()
    }
}

fn create_tls_volume(
    volume_name: &str,
    tls_secret_class: &str,
    requested_secret_lifetime: &Duration,
) -> Result<Volume> {
    Ok(VolumeBuilder::new(volume_name)
        .ephemeral(
            SecretOperatorVolumeSourceBuilder::new(tls_secret_class)
                .with_pod_scope()
                .with_node_scope()
                .with_format(SecretFormat::TlsPkcs12)
                .with_auto_tls_cert_lifetime(*requested_secret_lifetime)
                .build()
                .context(TlsCertSecretClassVolumeBuildSnafu)?,
        )
        .build())
}

fn tls_volume_mounts(
    trino: &TrinoCluster,
    pod_builder: &mut PodBuilder,
    cb_prepare: &mut ContainerBuilder,
    cb_trino: &mut ContainerBuilder,
    catalogs: &[CatalogConfig],
    requested_secret_lifetime: &Duration,
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

    Ok(())
}

#[cfg(test)]
mod tests {
    use stackable_operator::commons::networking::DomainName;

    use super::*;

    #[test]
    fn test_config_overrides() {
        let trino_yaml = r#"
        apiVersion: trino.stackable.tech/v1alpha1
        kind: TrinoCluster
        metadata:
          name: simple-trino
        spec:
          image:
            productVersion: "469"
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
        let cm = build_config_map(trino_yaml).data.unwrap();
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
    }

    fn build_config_map(trino_yaml: &str) -> ConfigMap {
        let mut trino: TrinoCluster = serde_yaml::from_str(trino_yaml).expect("illegal test input");
        trino.metadata.namespace = Some("default".to_owned());
        trino.metadata.uid = Some("42".to_owned());
        let cluster_info = KubernetesClusterInfo {
            cluster_domain: DomainName::try_from("cluster.local").unwrap(),
        };
        let resolved_product_image = trino
            .spec
            .image
            .resolve(DOCKER_IMAGE_BASE_NAME, "0.0.0-dev");

        let config_files = vec![
            PropertyNameKind::File(CONFIG_PROPERTIES.to_string()),
            PropertyNameKind::File(NODE_PROPERTIES.to_string()),
            PropertyNameKind::File(JVM_CONFIG.to_string()),
            PropertyNameKind::File(LOG_PROPERTIES.to_string()),
            PropertyNameKind::File(JVM_SECURITY_PROPERTIES.to_string()),
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
                            trino.spec.coordinators.clone().unwrap(),
                        ),
                    ),
                    (
                        TrinoRole::Worker.to_string(),
                        (config_files, trino.spec.workers.clone().unwrap()),
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
        let merged_config = trino
            .merged_config(&trino_role, &rolegroup_ref, &[])
            .unwrap();

        build_rolegroup_config_map(
            &trino,
            &resolved_product_image,
            role,
            &trino_role,
            &rolegroup_ref,
            validated_config
                .get("coordinator")
                .unwrap()
                .get("default")
                .unwrap(),
            &merged_config,
            &trino_authentication_config,
            &None,
            None,
            &cluster_info,
        )
        .unwrap()
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
            productVersion: "469"
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
        let trino: TrinoCluster =
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
