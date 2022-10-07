//! Ensures that `Pod`s are configured and running for each [`TrinoCluster`]
use crate::{
    catalog::{config::CatalogConfig, FromTrinoCatalogError},
    command, config,
    config::{password_authenticator_properties, LDAP_TRUST_CERT_PATH},
};
use indoc::formatdoc;
use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::commons::tls::{CaCert, Tls, TlsServerVerification, TlsVerification};
use stackable_operator::{
    builder::{
        ConfigMapBuilder, ContainerBuilder, ObjectMetaBuilder, PodBuilder,
        PodSecurityContextBuilder, SecretOperatorVolumeSourceBuilder, SecurityContextBuilder,
        VolumeBuilder,
    },
    client::Client,
    commons::{
        opa::OpaApiVersion,
        resources::{NoRuntimeLimits, Resources},
    },
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
    },
    kube::{
        runtime::{controller::Action, reflector::ObjectRef},
        ResourceExt,
    },
    labels::{role_group_selector_labels, role_selector_labels},
    logging::controller::ReconcilerError,
    memory::{to_java_heap_value, BinaryMultiple},
    product_config::{self, types::PropertyNameKind, ProductConfigManager},
    product_config_utils::{
        transform_all_roles_to_config, validate_all_roles_and_groups_config,
        ValidatedRoleConfigByPropertyKind,
    },
    role_utils::RoleGroupRef,
};
use stackable_trino_crd::{
    authentication,
    authentication::TrinoAuthenticationConfig,
    catalog::TrinoCatalog,
    discovery::{TrinoDiscovery, TrinoDiscoveryProtocol, TrinoPodRef},
    TlsSecretClass, TrinoCluster, TrinoRole, TrinoStorageConfig, ACCESS_CONTROL_PROPERTIES,
    APP_NAME, CONFIG_DIR_NAME, CONFIG_PROPERTIES, DATA_DIR_NAME, DISCOVERY_URI,
    ENV_INTERNAL_SECRET, HTTPS_PORT, HTTPS_PORT_NAME, HTTP_PORT, HTTP_PORT_NAME, JVM_CONFIG,
    JVM_HEAP_FACTOR, LDAP_PASSWORD_ENV, LDAP_USER_ENV, LOG_PROPERTIES, METRICS_PORT,
    METRICS_PORT_NAME, NODE_PROPERTIES, PASSWORD_AUTHENTICATOR_PROPERTIES, PASSWORD_DB,
    RW_CONFIG_DIR_NAME, STACKABLE_CLIENT_TLS_DIR, STACKABLE_INTERNAL_TLS_DIR,
    STACKABLE_MOUNT_INTERNAL_TLS_DIR, STACKABLE_MOUNT_SERVER_TLS_DIR, STACKABLE_SERVER_TLS_DIR,
    STACKABLE_TLS_STORE_PASSWORD, USER_PASSWORD_DATA_DIR_NAME,
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

pub const FIELD_MANAGER_SCOPE: &str = "trinocluster";
const CONTROLLER_NAME: &str = "trino-operator";

#[derive(Snafu, Debug, EnumDiscriminants)]
#[strum_discriminants(derive(IntoStaticStr))]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[snafu(display("object defines no namespace"))]
    ObjectHasNoNamespace,
    #[snafu(display("object defines no {} role", role))]
    MissingTrinoRole { role: String },
    #[snafu(display("failed to calculate global service name"))]
    GlobalServiceNameNotFound,
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
    #[snafu(display("failed to load Product Config"))]
    ProductConfigLoadFailed,
    #[snafu(display("failed to processing authentication config element from k8s"))]
    FailedProcessingAuthentication { source: authentication::Error },
    #[snafu(display("internal operator failure"))]
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
    #[snafu(display("invalid S3 connection: {reason}"))]
    InvalidS3Connection { reason: String },
    #[snafu(display("failed to parse trino product version"))]
    TrinoProductVersionParseFailure { source: stackable_trino_crd::Error },
    #[snafu(display("failed to get associated TrinoCatalogs"))]
    GetCatalogs {
        source: stackable_operator::error::Error,
    },
    #[snafu(display("failed to parse {catalog}"))]
    ParseCatalog {
        source: FromTrinoCatalogError,
        catalog: ObjectRef<TrinoCatalog>,
    },
    #[snafu(display("failed to resolve and merge resource config for role and role group"))]
    FailedToResolveResourceConfig,
    #[snafu(display("invalid java heap config - missing default or value in crd?"))]
    InvalidJavaHeapConfig,
    #[snafu(display("failed to convert java heap config to unit [{unit}]"))]
    FailedToConvertJavaHeap {
        source: stackable_operator::error::Error,
        unit: String,
    },
    #[snafu(display("illegal container name: [{container_name}]"))]
    IllegalContainerName {
        source: stackable_operator::error::Error,
        container_name: String,
    },
    #[snafu(display("invalid trino config"))]
    InvalidTrinoConfig { source: config::ConfigError },
    #[snafu(display("failed to retrieve secret for internal communications"))]
    FailedToRetrieveInternalSecret {
        source: stackable_operator::error::Error,
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
    let trino_product_version = trino
        .product_version()
        .context(TrinoProductVersionParseFailureSnafu)?;

    let catalog_definitions = client
        .list_with_label_selector::<TrinoCatalog>(
            trino.metadata.namespace.as_deref(),
            &trino.spec.catalog_label_selector,
        )
        .await
        .context(GetCatalogsSnafu)?;
    let mut catalogs = vec![];
    for catalog in catalog_definitions {
        let catalog_ref = ObjectRef::from_obj(&catalog);
        let catalog_config =
            CatalogConfig::from_catalog(catalog, client)
                .await
                .context(ParseCatalogSnafu {
                    catalog: catalog_ref,
                })?;

        catalogs.push(catalog_config);
    }

    let validated_config =
        validated_product_config(&trino, &trino_product_version, &ctx.product_config)?;

    let authentication_config = user_authentication(&trino, client).await?;

    // Assemble the OPA connection string from the discovery and the given path if provided
    let opa_connect_string = if let Some(opa_config) = &trino.spec.opa {
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

    let coordinator_role_service = build_coordinator_role_service(&trino)?;

    client
        .apply_patch(
            FIELD_MANAGER_SCOPE,
            &coordinator_role_service,
            &coordinator_role_service,
        )
        .await
        .context(ApplyRoleServiceSnafu)?;

    create_shared_internal_secret(&trino, client).await?;

    for (role, role_config) in validated_config {
        let trino_role = TrinoRole::from_str(&role).context(InternalOperatorFailureSnafu)?;
        for (role_group, config) in role_config {
            let rolegroup = trino_role.rolegroup_ref(&trino, role_group);

            let resources = trino
                .resolve_resource_config_for_role_and_rolegroup(&trino_role, &rolegroup)
                .context(FailedToResolveResourceConfigSnafu)?;

            let rg_service = build_rolegroup_service(&trino, &rolegroup)?;
            let rg_configmap = build_rolegroup_config_map(
                &trino,
                &trino_role,
                &rolegroup,
                &config,
                opa_connect_string.as_deref(),
                &resources,
                authentication_config.as_ref(),
            )?;
            let rg_catalog_configmap =
                build_rolegroup_catalog_config_map(&trino, &rolegroup, &catalogs)?;
            let rg_stateful_set = build_rolegroup_statefulset(
                &trino,
                &trino_role,
                &rolegroup,
                &config,
                authentication_config.as_ref(),
                &catalogs,
                &resources,
            )?;

            client
                .apply_patch(FIELD_MANAGER_SCOPE, &rg_service, &rg_service)
                .await
                .with_context(|_| ApplyRoleGroupServiceSnafu {
                    rolegroup: rolegroup.clone(),
                })?;

            client
                .apply_patch(FIELD_MANAGER_SCOPE, &rg_configmap, &rg_configmap)
                .await
                .with_context(|_| ApplyRoleGroupConfigSnafu {
                    rolegroup: rolegroup.clone(),
                })?;

            client
                .apply_patch(
                    FIELD_MANAGER_SCOPE,
                    &rg_catalog_configmap,
                    &rg_catalog_configmap,
                )
                .await
                .with_context(|_| ApplyRoleGroupConfigSnafu {
                    rolegroup: rolegroup.clone(),
                })?;

            client
                .apply_patch(FIELD_MANAGER_SCOPE, &rg_stateful_set, &rg_stateful_set)
                .await
                .with_context(|_| ApplyRoleGroupStatefulSetSnafu {
                    rolegroup: rolegroup.clone(),
                })?;
        }
    }

    Ok(Action::await_change())
}

/// The coordinator-role service is the primary endpoint that should be used by clients that do not
/// perform internal load balancing, including targets outside of the cluster.
pub fn build_coordinator_role_service(trino: &TrinoCluster) -> Result<Service> {
    let role_name = TrinoRole::Coordinator.to_string();
    let role_svc_name = trino
        .coordinator_role_service_name()
        .context(GlobalServiceNameNotFoundSnafu)?;
    Ok(Service {
        metadata: ObjectMetaBuilder::new()
            .name_and_namespace(trino)
            .name(&role_svc_name)
            .ownerreference_from_resource(trino, None, Some(true))
            .context(ObjectMissingMetadataForOwnerRefSnafu)?
            .with_recommended_labels(
                trino,
                APP_NAME,
                trino
                    .image_version()
                    .context(TrinoProductVersionParseFailureSnafu)?,
                CONTROLLER_NAME,
                &role_name,
                "global",
            )
            .build(),
        spec: Some(ServiceSpec {
            ports: Some(service_ports(trino)),
            selector: Some(role_selector_labels(trino, APP_NAME, &role_name)),
            type_: Some(
                trino
                    .spec
                    .service_type
                    .clone()
                    .unwrap_or_default()
                    .to_string(),
            ),
            ..ServiceSpec::default()
        }),
        status: None,
    })
}

/// The rolegroup [`ConfigMap`] configures the rolegroup based on the configuration given by the administrator
fn build_rolegroup_config_map(
    trino: &TrinoCluster,
    role: &TrinoRole,
    rolegroup_ref: &RoleGroupRef<TrinoCluster>,
    config: &HashMap<PropertyNameKind, BTreeMap<String, String>>,
    opa_connect_string: Option<&str>,
    resources: &Resources<TrinoStorageConfig, NoRuntimeLimits>,
    authentication_config: Option<&TrinoAuthenticationConfig>,
) -> Result<ConfigMap> {
    let mut cm_conf_data = BTreeMap::new();

    let heap = to_java_heap_value(
        resources
            .memory
            .limit
            .as_ref()
            .context(InvalidJavaHeapConfigSnafu)?,
        JVM_HEAP_FACTOR,
        BinaryMultiple::Mebi,
    )
    .context(FailedToConvertJavaHeapSnafu {
        unit: BinaryMultiple::Mebi.to_java_memory_unit(),
    })?;

    // TODO: create via product config?
    // from https://trino.io/docs/current/installation/deployment.html#jvm-config
    let mut jvm_config = formatdoc!(
        "-server
        -Xms{heap}m
        -Xmx{heap}m
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
        "
    );

    // TODO: we support only one coordinator for now
    let coordinator_ref: TrinoPodRef = trino
        .coordinator_pods()
        .context(InternalOperatorFailureSnafu)?
        .next()
        .context(MissingCoordinatorPodsSnafu)?;

    for (property_name_kind, config) in config {
        let mut transformed_config: BTreeMap<String, Option<String>> = config
            .iter()
            .map(|(k, v)| (k.clone(), Some(v.clone())))
            .collect();

        match property_name_kind {
            PropertyNameKind::File(file_name) if file_name == CONFIG_PROPERTIES => {
                let protocol = if trino.get_internal_tls().is_some() {
                    TrinoDiscoveryProtocol::Https
                } else {
                    TrinoDiscoveryProtocol::Http
                };

                let discovery = TrinoDiscovery::new(&coordinator_ref, protocol);
                transformed_config
                    .insert(DISCOVERY_URI.to_string(), Some(discovery.discovery_uri()));

                let config_properties =
                    product_config::writer::to_java_properties_string(transformed_config.iter())
                        .context(FailedToWriteJavaPropertiesSnafu)?;

                cm_conf_data.insert(file_name.to_string(), config_properties);
            }

            PropertyNameKind::File(file_name) if file_name == NODE_PROPERTIES => {
                let node_properties =
                    product_config::writer::to_java_properties_string(transformed_config.iter())
                        .context(FailedToWriteJavaPropertiesSnafu)?;

                cm_conf_data.insert(file_name.to_string(), node_properties);
            }
            PropertyNameKind::File(file_name) if file_name == LOG_PROPERTIES => {
                let log_properties =
                    product_config::writer::to_java_properties_string(transformed_config.iter())
                        .context(FailedToWriteJavaPropertiesSnafu)?;

                cm_conf_data.insert(file_name.to_string(), log_properties);
            }
            // authentication is coordinator only
            PropertyNameKind::File(file_name)
                if file_name == PASSWORD_AUTHENTICATOR_PROPERTIES
                    && *role == TrinoRole::Coordinator =>
            {
                // depending on authentication we need to add more properties
                if let Some(auth) = authentication_config {
                    password_authenticator_properties(&mut transformed_config, auth)
                        .context(InvalidTrinoConfigSnafu)?;
                }

                let pw_authenticator_properties =
                    product_config::writer::to_java_properties_string(transformed_config.iter())
                        .context(FailedToWriteJavaPropertiesSnafu)?;

                cm_conf_data.insert(file_name.to_string(), pw_authenticator_properties);
            }
            PropertyNameKind::File(file_name) if file_name == PASSWORD_DB => {
                // make sure password db is created to fill it via container command scripts
                cm_conf_data.insert(file_name.to_string(), "".to_string());
            }
            PropertyNameKind::File(file_name) if file_name == JVM_CONFIG => {
                let _ = writeln!(jvm_config, "-javaagent:/stackable/jmx/jmx_prometheus_javaagent-0.16.1.jar={}:/stackable/jmx/config.yaml", METRICS_PORT);
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
                .with_recommended_labels(
                    trino,
                    APP_NAME,
                    trino
                        .image_version()
                        .context(TrinoProductVersionParseFailureSnafu)?,
                    CONTROLLER_NAME,
                    &rolegroup_ref.role,
                    &rolegroup_ref.role_group,
                )
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
                .with_recommended_labels(
                    trino,
                    APP_NAME,
                    trino
                        .image_version()
                        .context(TrinoProductVersionParseFailureSnafu)?,
                    CONTROLLER_NAME,
                    &rolegroup_ref.role,
                    &rolegroup_ref.role_group,
                )
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
fn build_rolegroup_statefulset(
    trino: &TrinoCluster,
    role: &TrinoRole,
    rolegroup_ref: &RoleGroupRef<TrinoCluster>,
    config: &HashMap<PropertyNameKind, BTreeMap<String, String>>,
    authentication_config: Option<&TrinoAuthenticationConfig>,
    catalogs: &[CatalogConfig],
    resources: &Resources<TrinoStorageConfig, NoRuntimeLimits>,
) -> Result<StatefulSet> {
    let mut cb_trino =
        ContainerBuilder::new(APP_NAME).with_context(|_| IllegalContainerNameSnafu {
            container_name: APP_NAME.to_string(),
        })?;
    let mut cb_prepare =
        ContainerBuilder::new("prepare").with_context(|_| IllegalContainerNameSnafu {
            container_name: "prepare".to_string(),
        })?;
    let mut pod_builder = PodBuilder::new();

    let rolegroup = role
        .get_spec(trino)
        .with_context(|| MissingTrinoRoleSnafu {
            role: role.to_string(),
        })?
        .role_groups
        .get(&rolegroup_ref.role_group);
    let trino_image_version = trino
        .image_version()
        .context(TrinoProductVersionParseFailureSnafu)?;

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
    if let Some(internal_secret) = env_var_from_secret(&Some(secret_name), ENV_INTERNAL_SECRET) {
        env.push(internal_secret);
    };

    // we need to mount ldap bind credentials from the secret as env vars
    if let Some(auth) = authentication_config {
        match auth {
            TrinoAuthenticationConfig::MultiUser { .. } => {}
            TrinoAuthenticationConfig::Ldap(ldap) => {
                if let Some(ldap_bind_secret) = &ldap.bind_credentials {
                    if let Some(ldap_user) = env_var_from_secret(
                        &Some(ldap_bind_secret.secret_class.clone()),
                        LDAP_USER_ENV,
                    ) {
                        env.push(ldap_user);
                    }

                    if let Some(ldap_password) = env_var_from_secret(
                        &Some(ldap_bind_secret.secret_class.clone()),
                        LDAP_PASSWORD_ENV,
                    ) {
                        env.push(ldap_password);
                    }
                }
            }
        }
    }

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
        authentication_config,
    )?;

    let container_prepare = cb_prepare
        .image("docker.stackable.tech/stackable/tools:0.2.0-stackable0")
        .command(vec!["/bin/bash".to_string(), "-c".to_string()])
        .args(command::container_prepare_args(
            trino,
            catalogs,
            authentication_config,
        ))
        .add_volume_mount("data", DATA_DIR_NAME)
        .add_volume_mount("rwconfig", RW_CONFIG_DIR_NAME)
        .security_context(SecurityContextBuilder::run_as_root())
        .build();

    let container_trino = cb_trino
        .image(format!(
            "docker.stackable.tech/stackable/trino:{}",
            trino_image_version
        ))
        .command(vec!["/bin/bash".to_string(), "-c".to_string()])
        .args(command::container_trino_args(
            authentication_config,
            catalogs,
        ))
        .add_env_vars(env)
        .add_volume_mount("data", DATA_DIR_NAME)
        .add_volume_mount("config", CONFIG_DIR_NAME)
        .add_volume_mount("rwconfig", RW_CONFIG_DIR_NAME)
        .add_volume_mount("catalog", format!("{}/catalog", CONFIG_DIR_NAME))
        .add_container_ports(container_ports(trino))
        .resources(resources.clone().into())
        .readiness_probe(readiness_probe(trino))
        .liveness_probe(liveness_probe(trino))
        .build();

    pod_builder
        .metadata_builder(|m| {
            m.with_recommended_labels(
                trino,
                APP_NAME,
                trino_image_version,
                CONTROLLER_NAME,
                &rolegroup_ref.role,
                &rolegroup_ref.role_group,
            )
        })
        .add_init_container(container_prepare)
        .add_container(container_trino)
        .add_volume(Volume {
            name: "config".to_string(),
            config_map: Some(ConfigMapVolumeSource {
                name: Some(rolegroup_ref.object_name()),
                ..ConfigMapVolumeSource::default()
            }),
            ..Volume::default()
        })
        .add_volume(
            VolumeBuilder::new("rwconfig")
                .with_empty_dir(Some(""), None)
                .build(),
        )
        .add_volume(Volume {
            name: "catalog".to_string(),
            config_map: Some(ConfigMapVolumeSource {
                name: Some(format!("{}-catalog", rolegroup_ref.object_name())),
                ..ConfigMapVolumeSource::default()
            }),
            ..Volume::default()
        })
        .security_context(PodSecurityContextBuilder::new().fs_group(1000).build());

    Ok(StatefulSet {
        metadata: ObjectMetaBuilder::new()
            .name_and_namespace(trino)
            .name(&rolegroup_ref.object_name())
            .ownerreference_from_resource(trino, None, Some(true))
            .context(ObjectMissingMetadataForOwnerRefSnafu)?
            .with_recommended_labels(
                trino,
                APP_NAME,
                trino_image_version,
                CONTROLLER_NAME,
                &rolegroup_ref.role,
                &rolegroup_ref.role_group,
            )
            .build(),
        spec: Some(StatefulSetSpec {
            pod_management_policy: Some("Parallel".to_string()),
            replicas: if trino.spec.stopped.unwrap_or(false) {
                Some(0)
            } else {
                rolegroup.and_then(|rg| rg.replicas).map(i32::from)
            },
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
            volume_claim_templates: Some(vec![resources
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
    rolegroup: &RoleGroupRef<TrinoCluster>,
) -> Result<Service> {
    Ok(Service {
        metadata: ObjectMetaBuilder::new()
            .name_and_namespace(trino)
            .name(&rolegroup.object_name())
            .ownerreference_from_resource(trino, None, Some(true))
            .context(ObjectMissingMetadataForOwnerRefSnafu)?
            .with_recommended_labels(
                trino,
                APP_NAME,
                trino
                    .image_version()
                    .context(TrinoProductVersionParseFailureSnafu)?,
                CONTROLLER_NAME,
                &rolegroup.role,
                &rolegroup.role_group,
            )
            .with_label("prometheus.io/scrape", "true")
            .build(),
        spec: Some(ServiceSpec {
            cluster_ip: Some("None".to_string()),
            ports: Some(service_ports(trino)),
            selector: Some(role_group_selector_labels(
                trino,
                APP_NAME,
                &rolegroup.role,
                &rolegroup.role_group,
            )),
            publish_not_ready_addresses: Some(true),
            ..ServiceSpec::default()
        }),
        status: None,
    })
}

pub fn error_policy(_error: &Error, _ctx: Arc<Ctx>) -> Action {
    Action::requeue(Duration::from_secs(5))
}

async fn user_authentication(
    trino: &TrinoCluster,
    client: &Client,
) -> Result<Option<TrinoAuthenticationConfig>> {
    Ok(match &trino.get_authentication() {
        Some(authentication) => Some(
            authentication
                .method
                .materialize(
                    client,
                    trino
                        .namespace()
                        .as_deref()
                        .context(ObjectHasNoNamespaceSnafu)?,
                )
                .await
                .context(FailedProcessingAuthenticationSnafu)?,
        ),
        _ => None,
    })
}

fn env_var_from_secret(secret_name: &Option<String>, env_var: &str) -> Option<EnvVar> {
    secret_name.as_ref().map(|secret| EnvVar {
        name: env_var.to_string(),
        value_from: Some(EnvVarSource {
            secret_key_ref: Some(SecretKeySelector {
                optional: Some(false),
                name: Some(secret.to_string()),
                key: env_var.to_string(),
            }),
            ..EnvVarSource::default()
        }),
        ..EnvVar::default()
    })
}

/// Defines all required roles and their required configuration.
///
/// The roles and their configs are then validated and complemented by the product config.
///
/// # Arguments
/// * `resource`        - The NifiCluster containing the role definitions.
/// * `version`         - The NifiCluster version.
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
        PropertyNameKind::File(PASSWORD_AUTHENTICATOR_PROPERTIES.to_string()),
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

async fn create_shared_internal_secret(trino: &TrinoCluster, client: &Client) -> Result<()> {
    let secret = build_shared_internal_secret(trino)?;
    if client
        .get_opt::<Secret>(&secret.name_any(), secret.namespace().as_deref())
        .await
        .context(FailedToRetrieveInternalSecretSnafu)?
        .is_none()
    {
        client
            .apply_patch(FIELD_MANAGER_SCOPE, &secret, &secret)
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

    if trino.http_port_enabled() {
        ports.push(ServicePort {
            name: Some(HTTP_PORT_NAME.to_string()),
            port: HTTP_PORT.into(),
            protocol: Some("TCP".to_string()),
            ..ServicePort::default()
        });
    }

    if trino.https_port_enabled() {
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

    if trino.http_port_enabled() {
        ports.push(ContainerPort {
            name: Some(HTTP_PORT_NAME.to_string()),
            container_port: HTTP_PORT.into(),
            protocol: Some("TCP".to_string()),
            ..ContainerPort::default()
        })
    }

    if trino.https_port_enabled() {
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
    let port_name = if trino.https_port_enabled() {
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
    let port_name = if trino.https_port_enabled() {
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

fn create_tls_volume(volume_name: &str, tls_secret_class: &TlsSecretClass) -> Volume {
    VolumeBuilder::new(volume_name)
        .ephemeral(
            SecretOperatorVolumeSourceBuilder::new(&tls_secret_class.secret_class)
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
    authentication_config: Option<&TrinoAuthenticationConfig>,
) -> Result<()> {
    if let Some(client_tls) = trino.get_client_tls() {
        cb_prepare.add_volume_mount("server-tls-mount", STACKABLE_MOUNT_SERVER_TLS_DIR);
        cb_trino.add_volume_mount("server-tls-mount", STACKABLE_MOUNT_SERVER_TLS_DIR);
        pod_builder.add_volume(create_tls_volume("server-tls-mount", client_tls));
    }

    cb_prepare.add_volume_mount("server-tls", STACKABLE_SERVER_TLS_DIR);
    cb_trino.add_volume_mount("server-tls", STACKABLE_SERVER_TLS_DIR);
    pod_builder.add_volume(
        VolumeBuilder::new("server-tls")
            .with_empty_dir(Some(""), None)
            .build(),
    );

    cb_prepare.add_volume_mount("client-tls", STACKABLE_CLIENT_TLS_DIR);
    cb_trino.add_volume_mount("client-tls", STACKABLE_CLIENT_TLS_DIR);
    pod_builder.add_volume(
        VolumeBuilder::new("client-tls")
            .with_empty_dir(Some(""), None)
            .build(),
    );

    if let Some(internal_tls) = trino.get_internal_tls() {
        cb_prepare.add_volume_mount("internal-tls-mount", STACKABLE_MOUNT_INTERNAL_TLS_DIR);
        cb_trino.add_volume_mount("internal-tls-mount", STACKABLE_MOUNT_INTERNAL_TLS_DIR);
        pod_builder.add_volume(create_tls_volume("internal-tls-mount", internal_tls));

        cb_prepare.add_volume_mount("internal-tls", STACKABLE_INTERNAL_TLS_DIR);
        cb_trino.add_volume_mount("internal-tls", STACKABLE_INTERNAL_TLS_DIR);
        pod_builder.add_volume(
            VolumeBuilder::new("internal-tls")
                .with_empty_dir(Some(""), None)
                .build(),
        );
    }

    // catalogs
    for catalog in catalogs {
        cb_prepare.add_volume_mounts(catalog.volume_mounts.clone());
        cb_trino.add_volume_mounts(catalog.volume_mounts.clone());
        pod_builder.add_volumes(catalog.volumes.clone());
    }

    // If authentication is required (tls already activated) add volume mount for user pw database
    if let Some(auth) = authentication_config {
        match auth {
            TrinoAuthenticationConfig::MultiUser { .. } => {
                cb_prepare.add_volume_mount("users", USER_PASSWORD_DATA_DIR_NAME);
                cb_trino.add_volume_mount("users", USER_PASSWORD_DATA_DIR_NAME);
                pod_builder.add_volume(
                    VolumeBuilder::new("users")
                        .with_empty_dir(Some(""), None)
                        .build(),
                );
            }
            TrinoAuthenticationConfig::Ldap(ldap) => {
                if let Some(Tls {
                    verification:
                        TlsVerification::Server(TlsServerVerification {
                            ca_cert: CaCert::SecretClass(secret_class_name),
                        }),
                }) = &ldap.tls
                {
                    cb_trino.add_volume_mount("ldap-tls-mount", LDAP_TRUST_CERT_PATH);
                    pod_builder.add_volume(create_tls_volume(
                        "ldap-tls-mount",
                        &TlsSecretClass {
                            secret_class: secret_class_name.clone(),
                        },
                    ));
                }
            }
        }
    }

    Ok(())
}
