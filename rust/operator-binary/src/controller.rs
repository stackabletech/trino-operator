//! Ensures that `Pod`s are configured and running for each [`TrinoCluster`]
use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::builder::{PodSecurityContextBuilder, VolumeBuilder};
use stackable_operator::commons::s3::{S3AccessStyle, S3ConnectionDef};
use stackable_operator::{
    builder::{ConfigMapBuilder, ContainerBuilder, ObjectMetaBuilder, PodBuilder},
    client::Client,
    commons::{opa::OpaApiVersion, s3::S3ConnectionSpec},
    k8s_openapi::{
        api::{
            apps::v1::{StatefulSet, StatefulSetSpec},
            core::v1::{
                CSIVolumeSource, ConfigMap, ConfigMapKeySelector, ConfigMapVolumeSource,
                ContainerPort, EnvVar, EnvVarSource, PersistentVolumeClaim,
                PersistentVolumeClaimSpec, Probe, ResourceRequirements, SecurityContext, Service,
                ServicePort, ServiceSpec, TCPSocketAction, Volume,
            },
        },
        apimachinery::pkg::{
            api::resource::Quantity, apis::meta::v1::LabelSelector, util::intstr::IntOrString,
        },
    },
    kube::{
        api::ObjectMeta,
        runtime::controller::{Action, Context},
        ResourceExt,
    },
    labels::{role_group_selector_labels, role_selector_labels},
    logging::controller::ReconcilerError,
    product_config,
    product_config::{types::PropertyNameKind, ProductConfigManager},
    product_config_utils::{
        transform_all_roles_to_config, validate_all_roles_and_groups_config,
        ValidatedRoleConfigByPropertyKind,
    },
    role_utils::RoleGroupRef,
};
use stackable_trino_crd::{
    authentication,
    authentication::TrinoAuthenticationConfig,
    discovery::{TrinoDiscovery, TrinoDiscoveryProtocol, TrinoPodRef},
    TrinoCluster, TrinoRole, ACCESS_CONTROL_PROPERTIES, APP_NAME, CONFIG_DIR_NAME,
    CONFIG_PROPERTIES, DATA_DIR_NAME, DISCOVERY_URI, FIELD_MANAGER_SCOPE, HIVE_PROPERTIES,
    HTTPS_PORT, HTTPS_PORT_NAME, HTTP_PORT, HTTP_PORT_NAME, JVM_CONFIG, KEYSTORE_DIR_NAME,
    LOG_PROPERTIES, METRICS_PORT, METRICS_PORT_NAME, NODE_PROPERTIES,
    PASSWORD_AUTHENTICATOR_PROPERTIES, PASSWORD_DB, RW_CONFIG_DIR_NAME, S3_ACCESS_KEY, S3_ENDPOINT,
    S3_PATH_STYLE_ACCESS, S3_SECRET_DIR_NAME, S3_SECRET_KEY, S3_SSL_ENABLED,
    USER_PASSWORD_DATA_DIR_NAME,
};
use std::{
    collections::{BTreeMap, HashMap},
    str::FromStr,
    sync::Arc,
    time::Duration,
};
use strum::{EnumDiscriminants, IntoStaticStr};

pub struct Ctx {
    pub client: stackable_operator::client::Client,
    pub product_config: ProductConfigManager,
}

#[derive(Snafu, Debug, EnumDiscriminants)]
#[strum_discriminants(derive(IntoStaticStr))]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[snafu(display("object defines no version"))]
    ObjectHasNoVersion,
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
    #[snafu(display("could not extract trino product version (x.x.x) from image: [{version}]. Expected format e.g. x.x.x-stackable0.1.0"))]
    FailedTrinoProductVersionRetrieval { version: String },
}

type Result<T, E = Error> = std::result::Result<T, E>;

impl ReconcilerError for Error {
    fn category(&self) -> &'static str {
        ErrorDiscriminants::from(self).into()
    }
}

const ENV_S3_ACCESS_KEY: &str = "S3_ACCESS_KEY";
const ENV_S3_SECRET_KEY: &str = "S3_SECRET_KEY";
const SECRET_KEY_S3_ACCESS_KEY: &str = "accessKey";
const SECRET_KEY_S3_SECRET_KEY: &str = "secretKey";

pub async fn reconcile_trino(trino: Arc<TrinoCluster>, ctx: Context<Ctx>) -> Result<Action> {
    tracing::info!("Starting reconcile");

    let client = &ctx.get_ref().client;
    let trino_product_version = trino_product_version(&trino)?;

    let mut validated_config = validated_product_config(
        &trino,
        &trino_product_version,
        &ctx.get_ref().product_config,
    )?;

    let s3_connection_def: &Option<S3ConnectionDef> = &trino.spec.s3;
    let s3_connection_spec: Option<S3ConnectionSpec> = if let Some(s3) = s3_connection_def {
        Some(
            s3.resolve(client, trino.namespace().as_deref())
                .await
                .context(ResolveS3ConnectionSnafu)?,
        )
    } else {
        None
    };

    match &s3_connection_spec {
        Some(
            s3_connection_spec @ S3ConnectionSpec {
                host: Some(_),
                access_style,
                credentials: secret_class,
                tls,
                ..
            },
        ) => {
            for role_config in &mut validated_config.values_mut() {
                for config in role_config.values_mut() {
                    let hive_properties = config
                        .entry(PropertyNameKind::File(HIVE_PROPERTIES.to_string()))
                        .or_default();
                    hive_properties.insert(
                        S3_ENDPOINT.to_string(),
                        s3_connection_spec.endpoint().unwrap(),
                    );
                    if secret_class.is_some() {
                        hive_properties.insert(
                            S3_ACCESS_KEY.to_string(),
                            format!("${{ENV:{ENV_S3_ACCESS_KEY}}}"),
                        );
                        hive_properties.insert(
                            S3_SECRET_KEY.to_string(),
                            format!("${{ENV:{ENV_S3_SECRET_KEY}}}"),
                        );
                    }
                    hive_properties.insert(S3_SSL_ENABLED.to_string(), tls.is_some().to_string());
                    hive_properties.insert(
                        S3_PATH_STYLE_ACCESS.to_string(),
                        (access_style == &Some(S3AccessStyle::Path)).to_string(),
                    );
                }
            }
        }
        Some(S3ConnectionSpec { host: None, .. }) => InvalidS3ConnectionSnafu {
            reason: "host is missing",
        }
        .fail()?,
        None => (),
    }

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

    for (role, role_config) in validated_config {
        let trino_role = TrinoRole::from_str(&role).context(InternalOperatorFailureSnafu)?;
        for (role_group, config) in role_config {
            let rolegroup = trino_role.rolegroup_ref(&trino, role_group);
            let rg_service = build_rolegroup_service(&trino, &rolegroup)?;
            let rg_configmap = build_rolegroup_config_map(
                &trino,
                &trino_role,
                &rolegroup,
                &config,
                opa_connect_string.as_deref(),
            )?;
            let rg_catalog_configmap =
                build_rolegroup_catalog_config_map(&trino, &rolegroup, &config)?;
            let rg_stateful_set = build_rolegroup_statefulset(
                &trino,
                &trino_role,
                &rolegroup,
                &config,
                authentication_config.to_owned(),
                s3_connection_spec.as_ref(),
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
                trino_image_version(trino)?,
                &role_name,
                "global",
            )
            .build(),
        spec: Some(ServiceSpec {
            ports: Some(service_ports(trino)),
            selector: Some(role_selector_labels(trino, APP_NAME, &role_name)),
            type_: Some("NodePort".to_string()),
            ..ServiceSpec::default()
        }),
        status: None,
    })
}

/// The rolegroup [`ConfigMap`] configures the rolegroup based on the configuration given by the administrator
fn build_rolegroup_config_map(
    trino: &TrinoCluster,
    _role: &TrinoRole,
    rolegroup_ref: &RoleGroupRef<TrinoCluster>,
    config: &HashMap<PropertyNameKind, BTreeMap<String, String>>,
    opa_connect_string: Option<&str>,
) -> Result<ConfigMap> {
    let mut cm_conf_data = BTreeMap::new();

    // TODO: create via product config?
    // from https://trino.io/docs/current/installation/deployment.html#jvm-config
    let mut jvm_config = "-server
        -Xmx16G
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
        -Djdk.nio.maxCachedBufferSize=2000000"
        .to_string();

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
                // TODO: make http / https configurable
                let discovery = TrinoDiscovery::new(&coordinator_ref, TrinoDiscoveryProtocol::Http);
                transformed_config.insert(
                    DISCOVERY_URI.to_string(),
                    Some(discovery.connection_string()),
                );

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
            PropertyNameKind::File(file_name) if file_name == PASSWORD_AUTHENTICATOR_PROPERTIES => {
                let pw_properties =
                    product_config::writer::to_java_properties_string(transformed_config.iter())
                        .context(FailedToWriteJavaPropertiesSnafu)?;
                cm_conf_data.insert(file_name.to_string(), pw_properties);
            }
            PropertyNameKind::File(file_name) if file_name == PASSWORD_DB => {
                // make sure password db is created to fill it via container command scripts
                cm_conf_data.insert(file_name.to_string(), "".to_string());
            }
            PropertyNameKind::File(file_name) if file_name == JVM_CONFIG => {
                jvm_config.push_str(&format!("\n-javaagent:/stackable/jmx/jmx_prometheus_javaagent-0.16.1.jar={}:/stackable/jmx/config.yaml", METRICS_PORT));
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
                    trino_image_version(trino)?,
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
    config: &HashMap<PropertyNameKind, BTreeMap<String, String>>,
) -> Result<ConfigMap> {
    let mut cm_hive_data = BTreeMap::new();

    for (property_name_kind, config) in config {
        let mut transformed_config: BTreeMap<String, Option<String>> = config
            .iter()
            .map(|(k, v)| (k.clone(), Some(v.clone())))
            .collect();

        match property_name_kind {
            PropertyNameKind::File(file_name) if file_name == HIVE_PROPERTIES => {
                if trino.spec.hive_config_map_name.is_some() {
                    // hive.metastore.uri will be added later via command script from the
                    // "HIVE" env variable
                    transformed_config
                        .insert("connector.name".to_string(), Some("hive".to_string()));

                    let config_properties = product_config::writer::to_java_properties_string(
                        transformed_config.iter(),
                    )
                    .context(FailedToWriteJavaPropertiesSnafu)?;

                    cm_hive_data.insert(file_name.to_string(), config_properties);
                }
            }
            _ => {}
        }
    }

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
                    trino_image_version(trino)?,
                    &rolegroup_ref.role,
                    &rolegroup_ref.role_group,
                )
                .build(),
        )
        .data(cm_hive_data)
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
    authentication_config: Option<TrinoAuthenticationConfig>,
    s3_connection: Option<&S3ConnectionSpec>,
) -> Result<StatefulSet> {
    let mut container_builder = ContainerBuilder::new(APP_NAME);
    let mut pod_builder = PodBuilder::new();

    let rolegroup = role
        .get_spec(trino)
        .with_context(|| MissingTrinoRoleSnafu {
            role: role.to_string(),
        })?
        .role_groups
        .get(&rolegroup_ref.role_group);
    let trino_image_version = trino_image_version(trino)?;

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

    if let Some(hive) = env_var_from_discovery_config_map(&trino.spec.hive_config_map_name, "HIVE")
    {
        env.push(hive);
    };

    // Add volume and volume mounts for s3 credentials
    if let Some(S3ConnectionSpec {
        credentials: Some(credentials),
        ..
    }) = s3_connection
    {
        pod_builder.add_volume(credentials.to_volume("s3-credentials"));
        container_builder.add_volume_mount("s3-credentials", S3_SECRET_DIR_NAME);
    }

    let mut container_prepare = ContainerBuilder::new("prepare")
        .image("docker.stackable.tech/stackable/tools:0.2.0-stackable0")
        .command(vec!["/bin/bash".to_string(), "-c".to_string()])
        .args(container_prepare_args())
        .add_volume_mount("data", DATA_DIR_NAME)
        .add_volume_mount("rwconfig", RW_CONFIG_DIR_NAME)
        .add_volume_mount("users", USER_PASSWORD_DATA_DIR_NAME)
        .add_volume_mount("keystore", KEYSTORE_DIR_NAME)
        .build();

    container_prepare
        .security_context
        .get_or_insert_with(SecurityContext::default)
        .run_as_user = Some(0);

    let container_trino = container_builder
        .image(format!(
            "docker.stackable.tech/stackable/trino:{}",
            trino_image_version
        ))
        .command(vec!["/bin/bash".to_string(), "-c".to_string()])
        .args(container_trino_args(
            trino,
            authentication_config,
            s3_connection,
        ))
        .add_env_vars(env)
        .add_volume_mount("data", DATA_DIR_NAME)
        .add_volume_mount("config", CONFIG_DIR_NAME)
        .add_volume_mount("rwconfig", RW_CONFIG_DIR_NAME)
        .add_volume_mount("users", USER_PASSWORD_DATA_DIR_NAME)
        .add_volume_mount("keystore", KEYSTORE_DIR_NAME)
        .add_volume_mount("catalog", format!("{}/catalog", CONFIG_DIR_NAME))
        .add_container_ports(container_ports(trino))
        .readiness_probe(readiness_probe(trino))
        .liveness_probe(liveness_probe(trino))
        .build();
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
            template: pod_builder
                .metadata_builder(|m| {
                    m.with_recommended_labels(
                        trino,
                        APP_NAME,
                        trino_image_version,
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
                .add_volume(
                    VolumeBuilder::new("users")
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
                .add_volume(Volume {
                    name: "keystore".to_string(),
                    csi: Some(CSIVolumeSource {
                        driver: "secrets.stackable.tech".to_string(),
                        volume_attributes: Some(get_stackable_secret_volume_attributes()),
                        ..CSIVolumeSource::default()
                    }),
                    ..Volume::default()
                })
                .security_context(PodSecurityContextBuilder::new().fs_group(1000).build())
                .build_template(),
            volume_claim_templates: Some(vec![PersistentVolumeClaim {
                metadata: ObjectMeta {
                    name: Some("data".to_string()),
                    ..ObjectMeta::default()
                },
                spec: Some(PersistentVolumeClaimSpec {
                    access_modes: Some(vec!["ReadWriteOnce".to_string()]),
                    resources: Some(ResourceRequirements {
                        requests: Some({
                            let mut map = BTreeMap::new();
                            map.insert("storage".to_string(), Quantity("1Gi".to_string()));
                            map
                        }),
                        ..ResourceRequirements::default()
                    }),
                    ..PersistentVolumeClaimSpec::default()
                }),
                ..PersistentVolumeClaim::default()
            }]),
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
                trino_image_version(trino)?,
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

/// Returns the provided docker image e.g. 0.0.377-stackable0
pub fn trino_image_version(trino: &TrinoCluster) -> Result<&str> {
    trino
        .spec
        .version
        .as_deref()
        .context(ObjectHasNoVersionSnafu)
}

/// Returns our semver representation for product config e.g. 0.0.377
pub fn trino_product_version(trino: &TrinoCluster) -> Result<String> {
    let image_version = trino_image_version(trino)?;
    let product_version = image_version
        .split('-')
        .collect::<Vec<_>>()
        .first()
        .cloned()
        .with_context(|| FailedTrinoProductVersionRetrievalSnafu {
            version: image_version.to_string(),
        })?;
    Ok(format!("0.0.{}", product_version))
}

pub fn error_policy(_error: &Error, _ctx: Context<Ctx>) -> Action {
    Action::requeue(Duration::from_secs(5))
}

async fn user_authentication(
    trino: &TrinoCluster,
    client: &Client,
) -> Result<Option<TrinoAuthenticationConfig>> {
    Ok(match &trino.spec.authentication {
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

fn container_prepare_args() -> Vec<String> {
    vec![[
        "echo Storing password",
        &format!("echo secret > {keystore_directory}/password", keystore_directory = KEYSTORE_DIR_NAME),
        "echo Cleaning up truststore - just in case",
        &format!("rm -f {keystore_directory}/truststore.p12", keystore_directory = KEYSTORE_DIR_NAME),
        "echo Creating truststore",
        &format!("keytool -importcert -file {keystore_directory}/ca.crt -keystore {keystore_directory}/truststore.p12 -storetype pkcs12 -noprompt -alias ca_cert -storepass secret", 
                 keystore_directory = KEYSTORE_DIR_NAME),
        "echo Creating certificate chain",
        &format!("cat {keystore_directory}/ca.crt {keystore_directory}/tls.crt > {keystore_directory}/chain.crt", keystore_directory = KEYSTORE_DIR_NAME),
        "echo Creating keystore",
        &format!("openssl pkcs12 -export -in {keystore_directory}/chain.crt -inkey {keystore_directory}/tls.key -out {keystore_directory}/keystore.p12 --passout file:{keystore_directory}/password", 
                 keystore_directory = KEYSTORE_DIR_NAME),
        "echo Cleaning up password",
        &format!("rm -f {keystore_directory}/password", keystore_directory = KEYSTORE_DIR_NAME),
        "echo chowning keystore directory",
        &format!("chown -R stackable:stackable {keystore_directory}", keystore_directory = KEYSTORE_DIR_NAME),
        "echo chmodding keystore directory",
        &format!("chmod -R a=,u=rwX {keystore_directory}", keystore_directory = KEYSTORE_DIR_NAME),
        "echo chowning data directory",
        &format!("chown -R stackable:stackable {data_directory}", data_directory = DATA_DIR_NAME),
        "echo chmodding data directory",
        &format!("chmod -R a=,u=rwX {data_directory}", data_directory = DATA_DIR_NAME),
        "echo chowning rwconf directory",
        &format!("chown -R stackable:stackable {rwconf_directory}", rwconf_directory = RW_CONFIG_DIR_NAME),
        "echo chmodding rwconf directory",
        &format!("chmod -R a=,u=rwX {rwconf_directory}", rwconf_directory = RW_CONFIG_DIR_NAME),
        "echo chowning users directory",
        &format!("chown -R stackable:stackable {users_directory}", users_directory = USER_PASSWORD_DATA_DIR_NAME),
        "echo chmodding users directory",
        &format!("chmod -R a=,u=rwX {users_directory}", users_directory = USER_PASSWORD_DATA_DIR_NAME),
    ].join(" && ")]
}

fn container_trino_args(
    trino: &TrinoCluster,
    user_authentication: Option<TrinoAuthenticationConfig>,
    s3_connection_spec: Option<&S3ConnectionSpec>,
) -> Vec<String> {
    let mut args = vec![
        // copy config files to a writeable empty folder
        format!(
            "echo copying {conf} to {rw_conf}",
            conf = CONFIG_DIR_NAME,
            rw_conf = RW_CONFIG_DIR_NAME
        ),
        format!(
            "cp -RL {conf}/* {rw_conf}",
            conf = CONFIG_DIR_NAME,
            rw_conf = RW_CONFIG_DIR_NAME
        ),
    ];

    // We need to read the provided s3 credentials from the secret operator / secret class folder
    // and export it to the required env variables in order for trino to pick them up
    // out of the config via e.g. ${ENV:S3_ACCESS_KEY}.
    if let Some(S3ConnectionSpec {
        credentials: Some(_),
        ..
    }) = s3_connection_spec
    {
        args.extend(vec![
            format!(
                "export {env_var}=$(cat {secret_dir}/{file_name})",
                env_var = ENV_S3_ACCESS_KEY,
                secret_dir = S3_SECRET_DIR_NAME,
                file_name = SECRET_KEY_S3_ACCESS_KEY
            ),
            format!(
                "export {env_var}=$(cat {secret_dir}/{file_name})",
                env_var = ENV_S3_SECRET_KEY,
                secret_dir = S3_SECRET_DIR_NAME,
                file_name = SECRET_KEY_S3_SECRET_KEY
            ),
        ]);
    }

    if let Some(auth) = user_authentication {
        let user_data = auth.to_trino_user_data();
        args.extend(vec![
            format!(
                "echo Writing user data to {path}/{db}",
                path = USER_PASSWORD_DATA_DIR_NAME,
                db = PASSWORD_DB
            ),
            format!(
                "echo '{data}' > {path}/{db} ",
                data = user_data,
                path = USER_PASSWORD_DATA_DIR_NAME,
                db = PASSWORD_DB
            ),
        ])
    }
    // hive required?
    if trino.spec.hive_config_map_name.is_some() {
        args.extend(vec![
            format!( "echo Writing HIVE connect string \"hive.metastore.uri=${{HIVE}}\" to {rw_conf}/catalog/{hive_properties}",
                     rw_conf = RW_CONFIG_DIR_NAME, hive_properties = HIVE_PROPERTIES
            ),
            format!( "echo \"hive.metastore.uri=${{HIVE}}\" >> {rw_conf}/catalog/{hive_properties}",
                     rw_conf = RW_CONFIG_DIR_NAME, hive_properties = HIVE_PROPERTIES
            )])
    }

    // start command
    args.push(format!(
        "bin/launcher run --etc-dir={conf} --data-dir={data}",
        conf = RW_CONFIG_DIR_NAME,
        data = DATA_DIR_NAME
    ));

    vec![args.join(" && ")]
}

fn env_var_from_discovery_config_map(
    config_map_name: &Option<String>,
    env_var: &str,
) -> Option<EnvVar> {
    config_map_name.as_ref().map(|cm_name| EnvVar {
        name: env_var.to_string(),
        value_from: Some(EnvVarSource {
            config_map_key_ref: Some(ConfigMapKeySelector {
                name: Some(cm_name.to_string()),
                key: env_var.to_string(),
                ..ConfigMapKeySelector::default()
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
    resource: &TrinoCluster,
    version: &str,
    product_config: &ProductConfigManager,
) -> Result<ValidatedRoleConfigByPropertyKind, Error> {
    let mut roles = HashMap::new();

    let config_files = vec![
        PropertyNameKind::File(CONFIG_PROPERTIES.to_string()),
        PropertyNameKind::File(HIVE_PROPERTIES.to_string()),
        PropertyNameKind::File(NODE_PROPERTIES.to_string()),
        PropertyNameKind::File(JVM_CONFIG.to_string()),
        PropertyNameKind::File(LOG_PROPERTIES.to_string()),
    ];

    roles.insert(
        TrinoRole::Coordinator.to_string(),
        (
            [
                config_files.clone(),
                vec![PropertyNameKind::File(
                    PASSWORD_AUTHENTICATOR_PROPERTIES.to_string(),
                )],
            ]
            .concat(),
            resource
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
            resource
                .spec
                .workers
                .clone()
                .with_context(|| MissingTrinoRoleSnafu {
                    role: TrinoRole::Worker.to_string(),
                })?,
        ),
    );

    let role_config =
        transform_all_roles_to_config(resource, roles).context(ProductConfigTransformSnafu)?;

    validate_all_roles_and_groups_config(version, &role_config, product_config, false, false)
        .context(InvalidProductConfigSnafu)
}

fn service_ports(trino: &TrinoCluster) -> Vec<ServicePort> {
    let mut ports = vec![
        ServicePort {
            name: Some(HTTP_PORT_NAME.to_string()),
            port: HTTP_PORT.into(),
            protocol: Some("TCP".to_string()),
            ..ServicePort::default()
        },
        ServicePort {
            name: Some(METRICS_PORT_NAME.to_string()),
            port: METRICS_PORT.into(),
            protocol: Some("TCP".to_string()),
            ..ServicePort::default()
        },
    ];

    if trino.spec.authentication.is_some() {
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
    let mut ports = vec![
        ContainerPort {
            name: Some(HTTP_PORT_NAME.to_string()),
            container_port: HTTP_PORT.into(),
            protocol: Some("TCP".to_string()),
            ..ContainerPort::default()
        },
        ContainerPort {
            name: Some(METRICS_PORT_NAME.to_string()),
            container_port: METRICS_PORT.into(),
            protocol: Some("TCP".to_string()),
            ..ContainerPort::default()
        },
    ];

    if trino.spec.authentication.is_some() {
        ports.push(ContainerPort {
            name: Some(HTTPS_PORT_NAME.to_string()),
            container_port: HTTPS_PORT.into(),
            protocol: Some("TCP".to_string()),
            ..ContainerPort::default()
        });
    }

    ports
}

fn get_stackable_secret_volume_attributes() -> BTreeMap<String, String> {
    let mut result = BTreeMap::new();
    result.insert(
        "secrets.stackable.tech/class".to_string(),
        "tls".to_string(),
    );
    result.insert(
        "secrets.stackable.tech/scope".to_string(),
        "node,pod".to_string(),
    );
    result
}

fn readiness_probe(trino: &TrinoCluster) -> Probe {
    let port_name = match trino.spec.authentication {
        Some(_) => HTTPS_PORT_NAME,
        _ => HTTP_PORT_NAME,
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
    let port_name = match trino.spec.authentication {
        Some(_) => HTTPS_PORT_NAME,
        _ => HTTP_PORT_NAME,
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
