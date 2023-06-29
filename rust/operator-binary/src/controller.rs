//! Ensures that `Pod`s are configured and running for each [`TrinoCluster`]
use crate::{
    authentication::{TrinoAuthenticationConfig, TrinoAuthenticationTypes},
    catalog::{config::CatalogConfig, FromTrinoCatalogError},
    command,
    product_logging::{get_log_properties, get_vector_toml, resolve_vector_aggregator_address},
};

use indoc::formatdoc;
use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::{
    builder::{
        resources::ResourceRequirementsBuilder, ConfigMapBuilder, ContainerBuilder,
        ObjectMetaBuilder, PodBuilder, PodSecurityContextBuilder,
        SecretOperatorVolumeSourceBuilder, VolumeBuilder,
    },
    client::Client,
    cluster_resources::{ClusterResourceApplyStrategy, ClusterResources},
    commons::{
        opa::OpaApiVersion, product_image_selection::ResolvedProductImage,
        rbac::build_rbac_resources,
    },
    k8s_openapi::{
        api::{
            apps::v1::{StatefulSet, StatefulSetSpec},
            core::v1::{
                ConfigMap, ConfigMapVolumeSource, ContainerPort, EmptyDirVolumeSource, EnvVar,
                EnvVarSource, Probe, Secret, SecretKeySelector, Service, ServicePort, ServiceSpec,
                TCPSocketAction, Volume,
            },
        },
        apimachinery::pkg::{
            api::resource::Quantity, apis::meta::v1::LabelSelector, util::intstr::IntOrString,
        },
    },
    kube::{
        runtime::{controller::Action, reflector::ObjectRef},
        Resource, ResourceExt,
    },
    labels::{role_group_selector_labels, role_selector_labels, ObjectLabels},
    logging::controller::ReconcilerError,
    memory::BinaryMultiple,
    memory::MemoryQuantity,
    product_config::{self, types::PropertyNameKind, ProductConfigManager},
    product_config_utils::{
        transform_all_roles_to_config, validate_all_roles_and_groups_config,
        ValidatedRoleConfigByPropertyKind,
    },
    product_logging::{
        self,
        spec::{
            ConfigMapLogConfig, ContainerLogConfig, ContainerLogConfigChoice,
            CustomContainerLogConfig,
        },
    },
    role_utils::RoleGroupRef,
    status::condition::{
        compute_conditions, operations::ClusterOperationsConditionBuilder,
        statefulset::StatefulSetConditionBuilder,
    },
};
use stackable_trino_crd::authentication::resolve_authentication_classes;
use stackable_trino_crd::{
    catalog::TrinoCatalog,
    discovery::{TrinoDiscovery, TrinoDiscoveryProtocol, TrinoPodRef},
    Container, TrinoCluster, TrinoClusterStatus, TrinoConfig, TrinoRole, ACCESS_CONTROL_PROPERTIES,
    APP_NAME, CONFIG_DIR_NAME, CONFIG_PROPERTIES, DATA_DIR_NAME, DISCOVERY_URI,
    ENV_INTERNAL_SECRET, HTTPS_PORT, HTTPS_PORT_NAME, HTTP_PORT, HTTP_PORT_NAME, JVM_CONFIG,
    JVM_HEAP_FACTOR, LOG_COMPRESSION, LOG_FORMAT, LOG_MAX_SIZE, LOG_MAX_TOTAL_SIZE, LOG_PATH,
    LOG_PROPERTIES, METRICS_PORT, METRICS_PORT_NAME, NODE_PROPERTIES, RW_CONFIG_DIR_NAME,
    STACKABLE_CLIENT_TLS_DIR, STACKABLE_INTERNAL_TLS_DIR, STACKABLE_MOUNT_INTERNAL_TLS_DIR,
    STACKABLE_MOUNT_SERVER_TLS_DIR, STACKABLE_SERVER_TLS_DIR, STACKABLE_TLS_STORE_PASSWORD,
};
use std::{
    collections::{BTreeMap, HashMap},
    fmt::Write,
    str::FromStr,
    sync::Arc,
    time::Duration,
};
use strum::{EnumDiscriminants, IntoStaticStr};

pub struct Ctx {
    pub client: stackable_operator::client::Client,
    pub product_config: ProductConfigManager,
}

pub const OPERATOR_NAME: &str = "trino.stackable.tech";
pub const CONTROLLER_NAME: &str = "trinocluster";
pub const TRINO_UID: i64 = 1000;

pub const STACKABLE_LOG_DIR: &str = "/stackable/log";
pub const STACKABLE_LOG_CONFIG_DIR: &str = "/stackable/log_config";

const TRINO_LOG_FILE_SIZE_IN_MIB: u32 = TRINO_LOG_FILE_TOTAL_SIZE_IN_MIB / 2;
const TRINO_LOG_FILE_TOTAL_SIZE_IN_MIB: u32 = 10;
const MAX_PREPARE_LOG_FILE_SIZE_IN_MIB: u32 = 1;
// Additional buffer space is not needed, as the `prepare` container already has sufficient buffer
// space and all containers share a single volume.
const LOG_VOLUME_SIZE_IN_MIB: u32 =
    TRINO_LOG_FILE_TOTAL_SIZE_IN_MIB + MAX_PREPARE_LOG_FILE_SIZE_IN_MIB;

const DOCKER_IMAGE_BASE_NAME: &str = "trino";

#[derive(Snafu, Debug, EnumDiscriminants)]
#[strum_discriminants(derive(IntoStaticStr))]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[snafu(display("object defines no namespace"))]
    ObjectHasNoNamespace,
    #[snafu(display("object defines no {} role", role))]
    MissingTrinoRole { role: String },
    #[snafu(display("failed to create cluster resources"))]
    CreateClusterResources {
        source: stackable_operator::error::Error,
    },
    #[snafu(display("failed to delete orphaned resources"))]
    DeleteOrphanedResources {
        source: stackable_operator::error::Error,
    },
    #[snafu(display("failed to apply global Service"))]
    ApplyRoleService {
        source: stackable_operator::error::Error,
    },
    #[snafu(display("failed to apply Service for {}", rolegroup))]
    ApplyRoleGroupService {
        source: stackable_operator::error::Error,
        rolegroup: RoleGroupRef<TrinoCluster>,
    },
    #[snafu(display("failed to build ConfigMap for {}", rolegroup))]
    BuildRoleGroupConfig {
        source: stackable_operator::error::Error,
        rolegroup: RoleGroupRef<TrinoCluster>,
    },
    #[snafu(display("failed to apply ConfigMap for {}", rolegroup))]
    ApplyRoleGroupConfig {
        source: stackable_operator::error::Error,
        rolegroup: RoleGroupRef<TrinoCluster>,
    },
    #[snafu(display("failed to apply StatefulSet for {}", rolegroup))]
    ApplyRoleGroupStatefulSet {
        source: stackable_operator::error::Error,
        rolegroup: RoleGroupRef<TrinoCluster>,
    },
    #[snafu(display("failed to apply internal secret"))]
    ApplyInternalSecret {
        source: stackable_operator::error::Error,
    },
    #[snafu(display("invalid product config"))]
    InvalidProductConfig {
        source: stackable_operator::error::Error,
    },
    #[snafu(display("object is missing metadata to build owner reference"))]
    ObjectMissingMetadataForOwnerRef {
        source: stackable_operator::error::Error,
    },
    #[snafu(display("failed to transform configs"))]
    ProductConfigTransform {
        source: stackable_operator::product_config_utils::ConfigError,
    },
    #[snafu(display("failed to format runtime properties"))]
    FailedToWriteJavaProperties {
        source: stackable_operator::product_config::writer::PropertiesWriterError,
    },
    #[snafu(display("failed to parse role: {source}"))]
    FailedToParseRole { source: strum::ParseError },
    #[snafu(display("internal operator failure: {source}"))]
    InternalOperatorFailure { source: stackable_trino_crd::Error },
    #[snafu(display("no coordinator pods found for discovery"))]
    MissingCoordinatorPods,
    #[snafu(display("invalid OpaConfig"))]
    InvalidOpaConfig {
        source: stackable_operator::error::Error,
    },
    #[snafu(display("failed to resolve S3 connection"))]
    ResolveS3Connection {
        source: stackable_operator::error::Error,
    },
    #[snafu(display("failed to get associated TrinoCatalogs"))]
    GetCatalogs {
        source: stackable_operator::error::Error,
    },
    #[snafu(display("failed to parse {catalog}"))]
    ParseCatalog {
        source: FromTrinoCatalogError,
        catalog: ObjectRef<TrinoCatalog>,
    },
    #[snafu(display("invalid memory resource configuration - missing default or value in crd?"))]
    MissingMemoryResourceConfig,
    #[snafu(display("could not convert / scale memory resource config to [{unit}]"))]
    FailedToConvertMemoryResourceConfig {
        source: stackable_operator::error::Error,
        unit: String,
    },
    #[snafu(display("failed to convert java heap config to unit [{unit}]"))]
    FailedToConvertMemoryResourceConfigToJavaHeap {
        source: stackable_operator::error::Error,
        unit: String,
    },
    #[snafu(display("illegal container name: [{container_name}]"))]
    IllegalContainerName {
        source: stackable_operator::error::Error,
        container_name: String,
    },
    #[snafu(display("failed to retrieve secret for internal communications"))]
    FailedToRetrieveInternalSecret {
        source: stackable_operator::error::Error,
    },
    #[snafu(display("failed to resolve and merge config for role and role group"))]
    FailedToResolveConfig { source: stackable_trino_crd::Error },
    #[snafu(display("failed to resolve the Vector aggregator address"))]
    ResolveVectorAggregatorAddress {
        source: crate::product_logging::Error,
    },
    #[snafu(display("failed to add the logging configuration to the ConfigMap [{cm_name}]"))]
    InvalidLoggingConfig {
        source: crate::product_logging::Error,
        cm_name: String,
    },
    #[snafu(display("failed to patch service account"))]
    ApplyServiceAccount {
        source: stackable_operator::error::Error,
    },
    #[snafu(display("failed to patch role binding"))]
    ApplyRoleBinding {
        source: stackable_operator::error::Error,
    },
    #[snafu(display("failed to update status"))]
    ApplyStatus {
        source: stackable_operator::error::Error,
    },
    #[snafu(display("failed to build RBAC resources"))]
    BuildRbacResources {
        source: stackable_operator::error::Error,
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
}

type Result<T, E = Error> = std::result::Result<T, E>;

impl ReconcilerError for Error {
    fn category(&self) -> &'static str {
        ErrorDiscriminants::from(self).into()
    }
}

pub async fn reconcile_trino(trino: Arc<TrinoCluster>, ctx: Arc<Ctx>) -> Result<Action> {
    tracing::info!("Starting reconcile");

    let client = &ctx.client;

    let resolved_product_image: ResolvedProductImage =
        trino.spec.image.resolve(DOCKER_IMAGE_BASE_NAME);

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
        &trino,
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
        trino.as_ref(),
        APP_NAME,
        cluster_resources.get_required_labels(),
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

    // Assemble the OPA connection string from the discovery and the given path if provided
    let opa_connect_string = if let Some(opa_config) = trino
        .spec
        .cluster_config
        .authorization
        .as_ref()
        .and_then(|authz| authz.opa.as_ref())
    {
        Some(
            opa_config
                .full_document_url_from_config_map(
                    client,
                    &*trino,
                    Some("allow"),
                    OpaApiVersion::V1,
                )
                .await
                .context(InvalidOpaConfigSnafu)?,
        )
    } else {
        None
    };

    let coordinator_role_service = build_coordinator_role_service(&trino, &resolved_product_image)?;

    cluster_resources
        .add(client, coordinator_role_service)
        .await
        .context(ApplyRoleServiceSnafu)?;

    create_shared_internal_secret(&trino, client).await?;

    let vector_aggregator_address = resolve_vector_aggregator_address(&trino, client)
        .await
        .context(ResolveVectorAggregatorAddressSnafu)?;

    let mut sts_cond_builder = StatefulSetConditionBuilder::default();

    for (role, role_config) in validated_config {
        let trino_role = TrinoRole::from_str(&role).context(FailedToParseRoleSnafu)?;
        for (role_group, config) in role_config {
            let rolegroup = trino_role.rolegroup_ref(&trino, role_group);

            let merged_config = trino
                .merged_config(&trino_role, &rolegroup, &catalog_definitions)
                .context(FailedToResolveConfigSnafu)?;

            let rg_service = build_rolegroup_service(&trino, &resolved_product_image, &rolegroup)?;
            let rg_configmap = build_rolegroup_config_map(
                &trino,
                &resolved_product_image,
                &trino_role,
                &rolegroup,
                &config,
                &merged_config,
                &trino_authentication_config,
                opa_connect_string.as_deref(),
                vector_aggregator_address.as_deref(),
            )?;
            let rg_catalog_configmap = build_rolegroup_catalog_config_map(
                &trino,
                &resolved_product_image,
                &rolegroup,
                &catalogs,
            )?;
            let rg_stateful_set = build_rolegroup_statefulset(
                &trino,
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
    }

    let cluster_operation_cond_builder =
        ClusterOperationsConditionBuilder::new(&trino.spec.cluster_operation);

    let status = TrinoClusterStatus {
        conditions: compute_conditions(
            trino.as_ref(),
            &[&sts_cond_builder, &cluster_operation_cond_builder],
        ),
    };

    cluster_resources
        .delete_orphaned_resources(client)
        .await
        .context(DeleteOrphanedResourcesSnafu)?;
    client
        .apply_patch_status(OPERATOR_NAME, &*trino, &status)
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
            .build(),
        spec: Some(ServiceSpec {
            ports: Some(service_ports(trino)),
            selector: Some(role_selector_labels(trino, APP_NAME, &role_name)),
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
    role: &TrinoRole,
    rolegroup_ref: &RoleGroupRef<TrinoCluster>,
    config: &HashMap<PropertyNameKind, BTreeMap<String, String>>,
    merged_config: &TrinoConfig,
    trino_authentication_config: &TrinoAuthenticationConfig,
    opa_connect_string: Option<&str>,
    vector_aggregator_address: Option<&str>,
) -> Result<ConfigMap> {
    let mut cm_conf_data = BTreeMap::new();

    let memory_unit = BinaryMultiple::Mebi;
    let heap_size = MemoryQuantity::try_from(
        merged_config
            .resources
            .memory
            .limit
            .as_ref()
            .context(MissingMemoryResourceConfigSnafu)?,
    )
    .context(FailedToConvertMemoryResourceConfigSnafu {
        unit: memory_unit.to_java_memory_unit(),
    })?
    .scale_to(memory_unit)
        * JVM_HEAP_FACTOR;

    // TODO: create via product config?
    // from https://trino.io/docs/current/installation/deployment.html#jvm-config
    let mut jvm_config = formatdoc!(
        "-server
        -Xms{heap}
        -Xmx{heap}
        -XX:-UseBiasedLocking
        -XX:+UseG1GC
        -XX:G1HeapRegionSize=32M
        -XX:+ExplicitGCInvokesConcurrent
        -XX:+ExitOnOutOfMemoryError
        -XX:+HeapDumpOnOutOfMemoryError
        -XX:-OmitStackTraceInFastThrow
        -XX:ReservedCodeCacheSize=512M
        -XX:PerMethodRecompilationCutoff=10000
        -XX:PerBytecodeRecompilationCutoff=10000
        -Djdk.attach.allowAttachSelf=true
        -Djdk.nio.maxCachedBufferSize=2000000
        -Djavax.net.ssl.trustStore={STACKABLE_CLIENT_TLS_DIR}/truststore.p12
        -Djavax.net.ssl.trustStorePassword={STACKABLE_TLS_STORE_PASSWORD}
        -Djavax.net.ssl.trustStoreType=pkcs12
        ",
        heap = heap_size.format_for_java().context(
            FailedToConvertMemoryResourceConfigToJavaHeapSnafu {
                unit: memory_unit.to_java_memory_unit(),
            }
        )?
    );

    // TODO: we support only one coordinator for now
    let coordinator_ref: TrinoPodRef = trino
        .coordinator_pods()
        .context(InternalOperatorFailureSnafu)?
        .next()
        .context(MissingCoordinatorPodsSnafu)?;

    // Add additional config files fore authentication
    cm_conf_data.extend(trino_authentication_config.config_files(role));

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
                        .config_properties(role)
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
                dynamic_resolved_config
                    .insert(DISCOVERY_URI.to_string(), Some(discovery.discovery_uri()));

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
                    Some(format!("{TRINO_LOG_FILE_SIZE_IN_MIB}MB")),
                );
                // The maximum size of all logfiles combined
                dynamic_resolved_config.insert(
                    LOG_MAX_TOTAL_SIZE.to_string(),
                    Some(format!("{TRINO_LOG_FILE_TOTAL_SIZE_IN_MIB}MB")),
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
            PropertyNameKind::File(file_name) if file_name == JVM_CONFIG => {
                let _ = writeln!(jvm_config, "-javaagent:/stackable/jmx/jmx_prometheus_javaagent.jar={}:/stackable/jmx/config.yaml", METRICS_PORT);
            }
            _ => {}
        }
    }

    if let Some(opa_connect) = opa_connect_string {
        let mut opa_config = BTreeMap::new();
        opa_config.insert(
            "access-control.name".to_string(),
            Some("tech.stackable.trino.opa.OpaAuthorizer".to_string()),
        );
        opa_config.insert("opa.policy.uri".to_string(), Some(opa_connect.to_string()));

        let config_properties =
            product_config::writer::to_java_properties_string(opa_config.iter())
                .context(FailedToWriteJavaPropertiesSnafu)?;

        cm_conf_data.insert(ACCESS_CONTROL_PROPERTIES.to_string(), config_properties);
    }

    cm_conf_data.insert(JVM_CONFIG.to_string(), jvm_config.to_string());

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
    role: &TrinoRole,
    resolved_product_image: &ResolvedProductImage,
    rolegroup_ref: &RoleGroupRef<TrinoCluster>,
    config: &HashMap<PropertyNameKind, BTreeMap<String, String>>,
    merged_config: &TrinoConfig,
    trino_authentication_config: &TrinoAuthenticationConfig,
    catalogs: &[CatalogConfig],
    sa_name: &str,
) -> Result<StatefulSet> {
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

    let mut env = config
        .get(&PropertyNameKind::Env)
        .iter()
        .flat_map(|env_vars| env_vars.iter())
        .map(|(k, v)| EnvVar {
            name: k.clone(),
            value: Some(v.clone()),
            ..EnvVar::default()
        })
        .collect::<Vec<_>>();

    let secret_name = build_shared_internal_secret_name(trino);
    env.push(env_var_from_secret(&secret_name, None, ENV_INTERNAL_SECRET));

    trino_authentication_config.add_authentication_pod_and_volume_config(
        role.clone(),
        &mut pod_builder,
        &mut cb_prepare,
        &mut cb_trino,
    );

    // Add the needed stuff for catalogs
    env.extend(
        catalogs
            .iter()
            .flat_map(|catalog| &catalog.env_bindings)
            .cloned(),
    );

    // add volume mounts depending on the client tls, internal tls, catalogs and authentication
    tls_volume_mounts(
        trino,
        &mut pod_builder,
        &mut cb_prepare,
        &mut cb_trino,
        catalogs,
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

    let container_prepare = cb_prepare
        .image_from_product_image(resolved_product_image)
        .command(vec!["/bin/bash".to_string(), "-c".to_string()])
        .args(vec![prepare_args.join(" && ")])
        .add_volume_mount("data", DATA_DIR_NAME)
        .add_volume_mount("rwconfig", RW_CONFIG_DIR_NAME)
        .add_volume_mount("log-config", STACKABLE_LOG_CONFIG_DIR)
        .add_volume_mount("log", STACKABLE_LOG_DIR)
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
        .command(vec!["/bin/bash".to_string(), "-c".to_string()])
        .args(command::container_trino_args(
            trino_authentication_config,
            catalogs,
        ))
        .add_env_vars(env)
        .add_volume_mount("data", DATA_DIR_NAME)
        .add_volume_mount("config", CONFIG_DIR_NAME)
        .add_volume_mount("rwconfig", RW_CONFIG_DIR_NAME)
        .add_volume_mount("catalog", format!("{}/catalog", CONFIG_DIR_NAME))
        .add_volume_mount("log", STACKABLE_LOG_DIR)
        .add_container_ports(container_ports(trino))
        .resources(merged_config.resources.clone().into())
        .readiness_probe(readiness_probe(trino))
        .liveness_probe(liveness_probe(trino))
        .build();

    // add trino container first to better default into that container (e.g. instead of vector)
    pod_builder.add_container(container_trino);

    if let Some(ContainerLogConfig {
        choice:
            Some(ContainerLogConfigChoice::Custom(CustomContainerLogConfig {
                custom: ConfigMapLogConfig { config_map },
            })),
    }) = merged_config.logging.containers.get(&Container::Trino)
    {
        pod_builder.add_volume(Volume {
            name: "log-config".to_string(),
            config_map: Some(ConfigMapVolumeSource {
                name: Some(config_map.into()),
                ..ConfigMapVolumeSource::default()
            }),
            ..Volume::default()
        });
    } else {
        pod_builder.add_volume(Volume {
            name: "log-config".to_string(),
            config_map: Some(ConfigMapVolumeSource {
                name: Some(rolegroup_ref.object_name()),
                ..ConfigMapVolumeSource::default()
            }),
            ..Volume::default()
        });
    }

    if merged_config.logging.enable_vector_agent {
        pod_builder.add_container(product_logging::framework::vector_container(
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
        ));
    }

    pod_builder
        .metadata_builder(|m| {
            m.with_recommended_labels(build_recommended_labels(
                trino,
                &resolved_product_image.app_version_label,
                &rolegroup_ref.role,
                &rolegroup_ref.role_group,
            ));
            // This is actually used by some kuttl tests (as they don't specify the container explicitly)
            m.with_annotation("kubectl.kubernetes.io/default-container", "trino")
        })
        .image_pull_secrets_from_product_image(resolved_product_image)
        .affinity(&merged_config.affinity)
        .add_init_container(container_prepare)
        .add_volume(Volume {
            name: "config".to_string(),
            config_map: Some(ConfigMapVolumeSource {
                name: Some(rolegroup_ref.object_name()),
                ..ConfigMapVolumeSource::default()
            }),
            ..Volume::default()
        })
        .add_empty_dir_volume("rwconfig", None)
        .add_volume(Volume {
            name: "catalog".to_string(),
            config_map: Some(ConfigMapVolumeSource {
                name: Some(format!("{}-catalog", rolegroup_ref.object_name())),
                ..ConfigMapVolumeSource::default()
            }),
            ..Volume::default()
        })
        .add_volume(Volume {
            name: "log".to_string(),
            empty_dir: Some(EmptyDirVolumeSource {
                medium: None,
                size_limit: Some(Quantity(format!("{LOG_VOLUME_SIZE_IN_MIB}Mi"))),
            }),
            ..Volume::default()
        })
        .service_account_name(sa_name)
        .security_context(
            PodSecurityContextBuilder::new()
                .run_as_user(TRINO_UID)
                .run_as_group(0)
                .fs_group(1000)
                .build(),
        );
    Ok(StatefulSet {
        metadata: ObjectMetaBuilder::new()
            .name_and_namespace(trino)
            .name(&rolegroup_ref.object_name())
            .ownerreference_from_resource(trino, None, Some(true))
            .context(ObjectMissingMetadataForOwnerRefSnafu)?
            .with_recommended_labels(build_recommended_labels(
                trino,
                &resolved_product_image.app_version_label,
                &rolegroup_ref.role,
                &rolegroup_ref.role_group,
            ))
            .build(),
        spec: Some(StatefulSetSpec {
            pod_management_policy: Some("Parallel".to_string()),
            replicas: rolegroup.replicas.map(i32::from),
            selector: LabelSelector {
                match_labels: Some(role_group_selector_labels(
                    trino,
                    APP_NAME,
                    &rolegroup_ref.role,
                    &rolegroup_ref.role_group,
                )),
                ..LabelSelector::default()
            },
            service_name: rolegroup_ref.object_name(),
            template: pod_builder.build_template(),
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
            .name(&rolegroup_ref.object_name())
            .ownerreference_from_resource(trino, None, Some(true))
            .context(ObjectMissingMetadataForOwnerRefSnafu)?
            .with_recommended_labels(build_recommended_labels(
                trino,
                &resolved_product_image.app_version_label,
                &rolegroup_ref.role,
                &rolegroup_ref.role_group,
            ))
            .with_label("prometheus.io/scrape", "true")
            .build(),
        spec: Some(ServiceSpec {
            // Internal communication does not need to be exposed
            type_: Some("ClusterIP".to_string()),
            cluster_ip: Some("None".to_string()),
            ports: Some(service_ports(trino)),
            selector: Some(role_group_selector_labels(
                trino,
                APP_NAME,
                &rolegroup_ref.role,
                &rolegroup_ref.role_group,
            )),
            publish_not_ready_addresses: Some(true),
            ..ServiceSpec::default()
        }),
        status: None,
    })
}

pub fn error_policy(_obj: Arc<TrinoCluster>, _error: &Error, _ctx: Arc<Ctx>) -> Action {
    Action::requeue(Duration::from_secs(5))
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
                name: Some(secret_name.to_string()),
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
        PropertyNameKind::File(CONFIG_PROPERTIES.to_string()),
        PropertyNameKind::File(NODE_PROPERTIES.to_string()),
        PropertyNameKind::File(JVM_CONFIG.to_string()),
        PropertyNameKind::File(LOG_PROPERTIES.to_string()),
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

fn create_tls_volume(volume_name: &str, tls_secret_class: &str) -> Volume {
    VolumeBuilder::new(volume_name)
        .ephemeral(
            SecretOperatorVolumeSourceBuilder::new(tls_secret_class)
                .with_pod_scope()
                .with_node_scope()
                .build(),
        )
        .build()
}

fn tls_volume_mounts(
    trino: &TrinoCluster,
    pod_builder: &mut PodBuilder,
    cb_prepare: &mut ContainerBuilder,
    cb_trino: &mut ContainerBuilder,
    catalogs: &[CatalogConfig],
) -> Result<()> {
    if let Some(server_tls) = trino.get_server_tls() {
        cb_prepare.add_volume_mount("server-tls-mount", STACKABLE_MOUNT_SERVER_TLS_DIR);
        cb_trino.add_volume_mount("server-tls-mount", STACKABLE_MOUNT_SERVER_TLS_DIR);
        pod_builder.add_volume(create_tls_volume("server-tls-mount", server_tls));
    }

    cb_prepare.add_volume_mount("server-tls", STACKABLE_SERVER_TLS_DIR);
    cb_trino.add_volume_mount("server-tls", STACKABLE_SERVER_TLS_DIR);
    pod_builder.add_empty_dir_volume("server-tls", None);

    cb_prepare.add_volume_mount("client-tls", STACKABLE_CLIENT_TLS_DIR);
    cb_trino.add_volume_mount("client-tls", STACKABLE_CLIENT_TLS_DIR);
    pod_builder.add_empty_dir_volume("client-tls", None);

    if let Some(internal_tls) = trino.get_internal_tls() {
        cb_prepare.add_volume_mount("internal-tls-mount", STACKABLE_MOUNT_INTERNAL_TLS_DIR);
        cb_trino.add_volume_mount("internal-tls-mount", STACKABLE_MOUNT_INTERNAL_TLS_DIR);
        pod_builder.add_volume(create_tls_volume("internal-tls-mount", internal_tls));

        cb_prepare.add_volume_mount("internal-tls", STACKABLE_INTERNAL_TLS_DIR);
        cb_trino.add_volume_mount("internal-tls", STACKABLE_INTERNAL_TLS_DIR);
        pod_builder.add_empty_dir_volume("internal-tls", None);
    }

    // catalogs
    for catalog in catalogs {
        cb_prepare.add_volume_mounts(catalog.volume_mounts.clone());
        cb_trino.add_volume_mounts(catalog.volume_mounts.clone());
        pod_builder.add_volumes(catalog.volumes.clone());
    }

    Ok(())
}
