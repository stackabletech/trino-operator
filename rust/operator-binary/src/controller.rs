//! Ensures that `Pod`s are configured and running for each [`TrinoCluster`]
use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::client::Client;
use stackable_operator::k8s_openapi::api::core::v1::{ExecAction, Probe, Secret};
use stackable_operator::role_utils::RoleGroupRef;
use stackable_operator::{
    builder::{ConfigMapBuilder, ContainerBuilder, ObjectMetaBuilder, PodBuilder},
    k8s_openapi::{
        api::{
            apps::v1::{StatefulSet, StatefulSetSpec},
            core::v1::{
                ConfigMap, ConfigMapVolumeSource, EnvVar, PersistentVolumeClaim,
                PersistentVolumeClaimSpec, ResourceRequirements, Service, ServicePort, ServiceSpec,
                Volume,
            },
        },
        apimachinery::pkg::{api::resource::Quantity, apis::meta::v1::LabelSelector},
    },
    kube::{
        api::ObjectMeta,
        runtime::controller::{Context, ReconcilerAction},
    },
    labels::{role_group_selector_labels, role_selector_labels},
    product_config,
    product_config::{types::PropertyNameKind, ProductConfigManager},
    product_config_utils::{transform_all_roles_to_config, validate_all_roles_and_groups_config},
};
use stackable_trino_crd::authentication::{BasicAuthentication, SecretRef};
use stackable_trino_crd::authorization::create_rego_rules;
use stackable_trino_crd::discovery::{TrinoDiscovery, TrinoDiscoveryProtocol, TrinoPodRef};
use stackable_trino_crd::{
    TrinoCluster, TrinoClusterSpec, CONFIG_DIR_NAME, CONFIG_PROPERTIES, DATA_DIR_NAME,
    DISCOVERY_URI, HIVE_PROPERTIES, HTTPS_PORT, HTTPS_PORT_NAME, HTTP_PORT_NAME, JVM_CONFIG,
    LOG_PROPERTIES, METRICS_PORT, METRICS_PORT_NAME, NODE_PROPERTIES,
    PASSWORD_AUTHENTICATOR_PROPERTIES, PASSWORD_DB, TLS_DIR_NAME,
};
use stackable_trino_crd::{TrinoRole, APP_NAME, HTTP_PORT};
use std::{
    collections::{BTreeMap, HashMap},
    time::Duration,
};

const FIELD_MANAGER_SCOPE: &str = "trinocluster";

pub struct Ctx {
    pub client: stackable_operator::client::Client,
    pub product_config: ProductConfigManager,
}

#[derive(Snafu, Debug)]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[snafu(display("object defines no version"))]
    ObjectHasNoVersion,
    #[snafu(display("object defines no {} role", role))]
    MissingTrinoRole { role: String },
    #[snafu(display("failed to calculate global service name"))]
    GlobalServiceNameNotFound,
    #[snafu(display("failed to calculate service name for role {}", rolegroup))]
    RoleGroupServiceNameNotFound {
        rolegroup: RoleGroupRef<TrinoCluster>,
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
    #[snafu(display("invalid product config"))]
    InvalidProductConfig {
        source: stackable_operator::error::Error,
    },
    #[snafu(display("object is missing metadata to build owner reference"))]
    ObjectMissingMetadataForOwnerRef {
        source: stackable_operator::error::Error,
    },
    #[snafu(display("failed to update status"))]
    ApplyStatus {
        source: stackable_operator::error::Error,
    },
    #[snafu(display("failed to transform configs"))]
    ProductConfigTransform {
        source: stackable_operator::product_config_utils::ConfigError,
    },
    #[snafu(display("failed to format runtime properties"))]
    PropertiesWriteError {
        source: stackable_operator::product_config::writer::PropertiesWriterError,
    },
    #[snafu(display("operator-rs reported error"))]
    OperatorFrameworkError {
        source: stackable_operator::error::Error,
    },
    #[snafu(display("failed to get config map [{}/{}]", namespace, name,))]
    MissingConfigMap {
        source: stackable_operator::error::Error,
        name: String,
        namespace: String,
    },
    #[snafu(display(
        "failed to get [{}] connection string from config map [{}/{}]",
        product,
        namespace,
        name
    ))]
    MissingConnectString {
        product: String,
        name: String,
        namespace: String,
    },
    #[snafu(display("failed to retrieve secret [{}/{}]", namespace, name))]
    MissingSecret {
        source: stackable_operator::error::Error,
        name: String,
        namespace: String,
    },
    #[snafu(display("no secrets were provided in the custom resource"))]
    MissingSecretInCrd,
    #[snafu(display("failed to retrieve string data from secret [{}/{}]", namespace, name))]
    MissingStringDataInSecret { name: String, namespace: String },
    #[snafu(display(
        "failed to retrieve property [{}] from secret [{}/{}]",
        property,
        namespace,
        name
    ))]
    MissingPropertyInSecretData {
        property: String,
        name: String,
        namespace: String,
    },
}

type Result<T, E = Error> = std::result::Result<T, E>;

pub async fn reconcile_trino(trino: TrinoCluster, ctx: Context<Ctx>) -> Result<ReconcilerAction> {
    tracing::info!("Starting reconcile");

    let client = &ctx.get_ref().client;
    let version = trino_version(&trino)?;
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
                vec![
                    PropertyNameKind::File(PASSWORD_AUTHENTICATOR_PROPERTIES.to_string()),
                    PropertyNameKind::File(PASSWORD_DB.to_string()),
                ],
            ]
            .concat(),
            trino
                .spec
                .coordinators
                .clone()
                .with_context(|| MissingTrinoRole {
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
                .with_context(|| MissingTrinoRole {
                    role: TrinoRole::Worker.to_string(),
                })?,
        ),
    );

    // rego rules
    create_rego_rules(client, &trino)
        .await
        .context(OperatorFrameworkError)?;

    let role_config =
        transform_all_roles_to_config(&trino, roles).context(ProductConfigTransform)?;

    let validated_config = validate_all_roles_and_groups_config(
        version,
        &role_config,
        &ctx.get_ref().product_config,
        false,
        false,
    )
    .context(InvalidProductConfig)?;

    let coordinator_role_service = build_coordinator_role_service(&trino)?;
    client
        .apply_patch(
            FIELD_MANAGER_SCOPE,
            &coordinator_role_service,
            &coordinator_role_service,
        )
        .await
        .context(ApplyRoleService)?;

    let opa_connect = opa_connect(&trino, &ctx.get_ref().client).await?;
    let hive_connect = hive_connect(&trino, &ctx.get_ref().client).await?;
    // tls configuration config map name
    let tls_config_map_name = tls_config_map_exists(&trino, client).await?; //Some("trino-key-config".to_string());
    let basic_auth = match &trino.spec.authentication {
        Some(auth) => extract_basic_auth_from_secret(client, &auth.basic).await?,
        None => {
            println!("No basic auth provided!");
            Vec::new()
        }
    };

    for (role, role_config) in validated_config {
        let trino_role = TrinoRole::from(role);
        for (role_group, config) in role_config {
            let rolegroup = trino_role.rolegroup_ref(&trino, role_group);
            let rg_service = build_rolegroup_service(&trino, &rolegroup)?;
            let rg_configmap = build_rolegroup_config_map(
                &trino,
                &trino_role,
                &rolegroup,
                &config,
                &opa_connect,
                &basic_auth,
            )?;
            let rg_catalog_configmap =
                build_rolegroup_catalog_config_map(&trino, &rolegroup, &config, &hive_connect)?;
            let rg_stateful_set = build_rolegroup_statefulset(
                &trino,
                &trino_role,
                &rolegroup,
                &config,
                &tls_config_map_name,
            )?;

            client
                .apply_patch(FIELD_MANAGER_SCOPE, &rg_service, &rg_service)
                .await
                .with_context(|| ApplyRoleGroupService {
                    rolegroup: rolegroup.clone(),
                })?;

            client
                .apply_patch(FIELD_MANAGER_SCOPE, &rg_configmap, &rg_configmap)
                .await
                .with_context(|| ApplyRoleGroupConfig {
                    rolegroup: rolegroup.clone(),
                })?;

            client
                .apply_patch(
                    FIELD_MANAGER_SCOPE,
                    &rg_catalog_configmap,
                    &rg_catalog_configmap,
                )
                .await
                .with_context(|| ApplyRoleGroupConfig {
                    rolegroup: rolegroup.clone(),
                })?;

            client
                .apply_patch(FIELD_MANAGER_SCOPE, &rg_stateful_set, &rg_stateful_set)
                .await
                .with_context(|| ApplyRoleGroupStatefulSet {
                    rolegroup: rolegroup.clone(),
                })?;
        }
    }

    Ok(ReconcilerAction {
        requeue_after: None,
    })
}

/// The coordinator-role service is the primary endpoint that should be used by clients that do not
/// perform internal load balancing, including targets outside of the cluster.
pub fn build_coordinator_role_service(trino: &TrinoCluster) -> Result<Service> {
    let role_name = TrinoRole::Coordinator.to_string();
    let role_svc_name = trino
        .coordinator_role_service_name()
        .context(GlobalServiceNameNotFound)?;
    Ok(Service {
        metadata: ObjectMetaBuilder::new()
            .name_and_namespace(trino)
            .name(&role_svc_name)
            .ownerreference_from_resource(trino, None, Some(true))
            .context(ObjectMissingMetadataForOwnerRef)?
            .with_recommended_labels(trino, APP_NAME, trino_version(trino)?, &role_name, "global")
            .build(),
        spec: Some(ServiceSpec {
            ports: Some(vec![
                ServicePort {
                    name: Some(HTTP_PORT_NAME.to_string()),
                    port: HTTP_PORT.into(),
                    protocol: Some("TCP".to_string()),
                    ..ServicePort::default()
                },
                ServicePort {
                    name: Some(HTTPS_PORT_NAME.to_string()),
                    port: HTTPS_PORT.into(),
                    protocol: Some("TCP".to_string()),
                    ..ServicePort::default()
                },
                ServicePort {
                    name: Some(METRICS_PORT_NAME.to_string()),
                    port: METRICS_PORT.into(),
                    protocol: Some("TCP".to_string()),
                    ..ServicePort::default()
                },
            ]),
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
    opa_connect: &Option<String>,
    basic_auth: &Vec<BasicAuthentication>,
) -> Result<ConfigMap> {
    let mut cm_conf_data = BTreeMap::new();

    // TODO: create via product config?
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
    // TODO: remove unwrap
    let coordinator_ref: TrinoPodRef = trino.coordinator_pods().unwrap().next().unwrap();

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
                        .context(PropertiesWriteError)?;

                cm_conf_data.insert(file_name.to_string(), config_properties);
            }

            PropertyNameKind::File(file_name) if file_name == NODE_PROPERTIES => {
                let node_properties =
                    product_config::writer::to_java_properties_string(transformed_config.iter())
                        .context(PropertiesWriteError)?;

                cm_conf_data.insert(file_name.to_string(), node_properties);
            }
            PropertyNameKind::File(file_name) if file_name == LOG_PROPERTIES => {
                let log_properties =
                    product_config::writer::to_java_properties_string(transformed_config.iter())
                        .context(PropertiesWriteError)?;

                cm_conf_data.insert(file_name.to_string(), log_properties);
            }
            PropertyNameKind::File(file_name) if file_name == PASSWORD_AUTHENTICATOR_PROPERTIES => {
                let pw_properties =
                    product_config::writer::to_java_properties_string(transformed_config.iter())
                        .context(PropertiesWriteError)?;
                cm_conf_data.insert(file_name.to_string(), pw_properties);
            }
            PropertyNameKind::File(file_name) if file_name == PASSWORD_DB => {}
            PropertyNameKind::File(file_name) if file_name == JVM_CONFIG => {
                jvm_config.push_str(&format!("\n-javaagent:/stackable/jmx/jmx_prometheus_javaagent-0.16.1.jar={}:/stackable/jmx/config.yaml", METRICS_PORT));
            }
            _ => {}
        }
    }

    let pw_file_content = basic_auth
        .iter()
        .map(|auth| auth.combined())
        .collect::<Vec<_>>()
        .join("\n");
    cm_conf_data.insert(PASSWORD_DB.to_string(), pw_file_content.to_string());

    if let Some(opa) = opa_connect {
        let package = match trino.spec.authorization.as_ref() {
            Some(auth) => auth.package.clone(),
            None => {
                println!("No package specified in 'authorization'. Defaulting to 'trino'.");
                "trino".to_string()
            }
        };

        let mut opa_config = BTreeMap::new();

        opa_config.insert(
            "access-control.name".to_string(),
            Some("tech.stackable.trino.opa.OpaAuthorizer".to_string()),
        );
        opa_config.insert(
            "opa.policy.uri".to_string(),
            Some(format!("{}v1/data/{}/", opa, package)),
        );

        let config_properties =
            product_config::writer::to_java_properties_string(opa_config.iter())
                .context(PropertiesWriteError)?;

        cm_conf_data.insert("access-control.properties".to_string(), config_properties);
    }

    cm_conf_data.insert(JVM_CONFIG.to_string(), jvm_config.to_string());

    ConfigMapBuilder::new()
        .metadata(
            ObjectMetaBuilder::new()
                .name_and_namespace(trino)
                .name(rolegroup_ref.object_name())
                .ownerreference_from_resource(trino, None, Some(true))
                .context(ObjectMissingMetadataForOwnerRef)?
                .with_recommended_labels(
                    trino,
                    APP_NAME,
                    trino_version(trino)?,
                    &rolegroup_ref.role,
                    &rolegroup_ref.role_group,
                )
                .build(),
        )
        .data(cm_conf_data)
        .build()
        .with_context(|| BuildRoleGroupConfig {
            rolegroup: rolegroup_ref.clone(),
        })
}

/// The rolegroup catalog [`ConfigMap`] configures the rolegroup catalog based on the configuration
/// given by the administrator
fn build_rolegroup_catalog_config_map(
    trino: &TrinoCluster,
    rolegroup_ref: &RoleGroupRef<TrinoCluster>,
    config: &HashMap<PropertyNameKind, BTreeMap<String, String>>,
    hive_connect: &Option<String>,
) -> Result<ConfigMap> {
    let mut cm_hive_data = BTreeMap::new();

    for (property_name_kind, config) in config {
        let mut transformed_config: BTreeMap<String, Option<String>> = config
            .iter()
            .map(|(k, v)| (k.clone(), Some(v.clone())))
            .collect();

        match property_name_kind {
            PropertyNameKind::File(file_name) if file_name == HIVE_PROPERTIES => {
                if let Some(hive_connect) = &hive_connect {
                    transformed_config
                        .insert("connector.name".to_string(), Some("hive".to_string()));
                    transformed_config
                        .insert("hive.metastore.uri".to_string(), Some(hive_connect.clone()));

                    let config_properties = product_config::writer::to_java_properties_string(
                        transformed_config.iter(),
                    )
                    .context(PropertiesWriteError)?;

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
                .context(ObjectMissingMetadataForOwnerRef)?
                .with_recommended_labels(
                    trino,
                    APP_NAME,
                    trino_version(trino)?,
                    &rolegroup_ref.role,
                    &rolegroup_ref.role_group,
                )
                .build(),
        )
        .data(cm_hive_data)
        .build()
        .with_context(|| BuildRoleGroupConfig {
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
    tls_config_map_name: &Option<String>,
) -> Result<StatefulSet> {
    let rolegroup = role
        .get_spec(trino)
        .with_context(|| MissingTrinoRole {
            role: role.to_string(),
        })?
        .role_groups
        .get(&rolegroup_ref.role_group);
    let trino_version = trino_version_trim(trino)?;
    let image = format!(
        "docker.stackable.tech/stackable/trino:{}-stackable0",
        trino_version
    );
    let env = config
        .get(&PropertyNameKind::Env)
        .iter()
        .flat_map(|env_vars| env_vars.iter())
        .map(|(k, v)| EnvVar {
            name: k.clone(),
            value: Some(v.clone()),
            ..EnvVar::default()
        })
        .collect::<Vec<_>>();
    let container_trino = ContainerBuilder::new(APP_NAME)
        .image(image)
        .command(vec!["/bin/bash".to_string(), "-c".to_string()])
        .args(vec![format!(
            "bin/launcher run --etc-dir={}",
            CONFIG_DIR_NAME,
        )])
        .add_env_vars(env)
        .add_volume_mount("data", DATA_DIR_NAME)
        .add_volume_mount("conf", CONFIG_DIR_NAME)
        .add_volume_mount("tls", TLS_DIR_NAME)
        .add_volume_mount("catalog", format!("{}/catalog", CONFIG_DIR_NAME))
        .readiness_probe(Probe {
            exec: Some(ExecAction {
                command: Some(vec![
                    "/bin/bash".to_string(),
                    "-c".to_string(),
                    // TODO: check https as well? Or check logs for "======== SERVER STARTED ========"?
                    format!("curl http://localhost:{}", HTTP_PORT),
                ]),
            }),
            period_seconds: Some(1),
            ..Probe::default()
        })
        .build();
    Ok(StatefulSet {
        metadata: ObjectMetaBuilder::new()
            .name_and_namespace(trino)
            .name(&rolegroup_ref.object_name())
            .ownerreference_from_resource(trino, None, Some(true))
            .context(ObjectMissingMetadataForOwnerRef)?
            .with_recommended_labels(
                trino,
                APP_NAME,
                trino_version,
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
            template: PodBuilder::new()
                .metadata_builder(|m| {
                    m.with_recommended_labels(
                        trino,
                        APP_NAME,
                        trino_version,
                        &rolegroup_ref.role,
                        &rolegroup_ref.role_group,
                    )
                })
                .add_container(container_trino)
                .add_volume(Volume {
                    name: "conf".to_string(),
                    config_map: Some(ConfigMapVolumeSource {
                        name: Some(rolegroup_ref.object_name()),
                        ..ConfigMapVolumeSource::default()
                    }),
                    ..Volume::default()
                })
                .add_volume(Volume {
                    name: "catalog".to_string(),
                    config_map: Some(ConfigMapVolumeSource {
                        name: Some(format!("{}-catalog", rolegroup_ref.object_name())),
                        ..ConfigMapVolumeSource::default()
                    }),
                    ..Volume::default()
                })
                .add_volume(Volume {
                    name: "tls".to_string(),
                    config_map: Some(ConfigMapVolumeSource {
                        // TODO: remove unwrap
                        name: Some(tls_config_map_name.clone().unwrap()),
                        ..ConfigMapVolumeSource::default()
                    }),
                    ..Volume::default()
                })
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
            .context(ObjectMissingMetadataForOwnerRef)?
            .with_recommended_labels(
                trino,
                APP_NAME,
                trino_version(trino)?,
                &rolegroup.role,
                &rolegroup.role_group,
            )
            .build(),
        spec: Some(ServiceSpec {
            cluster_ip: Some("None".to_string()),
            ports: Some(vec![
                ServicePort {
                    name: Some(HTTP_PORT_NAME.to_string()),
                    port: HTTP_PORT.into(),
                    protocol: Some("TCP".to_string()),
                    ..ServicePort::default()
                },
                ServicePort {
                    name: Some(HTTPS_PORT_NAME.to_string()),
                    port: HTTPS_PORT.into(),
                    protocol: Some("TCP".to_string()),
                    ..ServicePort::default()
                },
                ServicePort {
                    name: Some(METRICS_PORT_NAME.to_string()),
                    port: METRICS_PORT.into(),
                    protocol: Some("TCP".to_string()),
                    ..ServicePort::default()
                },
            ]),
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

/// Returns our semver representation for product config e.g. 0.0.362
pub fn trino_version(trino: &TrinoCluster) -> Result<&str> {
    trino.spec.version.as_deref().context(ObjectHasNoVersion)
}

/// Returns the "real" Trino version for docker images e.g. 362
pub fn trino_version_trim(trino: &TrinoCluster) -> Result<&str> {
    let spec: &TrinoClusterSpec = &trino.spec;
    spec.version
        .as_deref()
        .and_then(|v| v.split('.').collect::<Vec<_>>().last().cloned())
        .context(ObjectHasNoVersion)
}

pub fn error_policy(_error: &Error, _ctx: Context<Ctx>) -> ReconcilerAction {
    ReconcilerAction {
        requeue_after: Some(Duration::from_secs(5)),
    }
}

async fn opa_connect(trino: &TrinoCluster, client: &Client) -> Result<Option<String>> {
    let spec: &TrinoClusterSpec = &trino.spec;
    let mut opa_connect_string = None;

    if let Some(opa_reference) = &spec.opa {
        let product = "OPA";
        let name = &opa_reference.name;
        let namespace = &opa_reference.namespace;

        opa_connect_string = Some(
            client
                .get::<ConfigMap>(name, Some(namespace))
                .await
                .with_context(|| MissingConfigMap {
                    name: name.clone(),
                    namespace: namespace.clone(),
                })?
                .data
                .and_then(|mut data| data.remove(product))
                .with_context(|| MissingConnectString {
                    product: product.to_string(),
                    name: name.clone(),
                    namespace: namespace.clone(),
                })?,
        );
    }

    Ok(opa_connect_string)
}

async fn hive_connect(trino: &TrinoCluster, client: &Client) -> Result<Option<String>> {
    let spec: &TrinoClusterSpec = &trino.spec;
    let mut hive_connect_string = None;

    if let Some(hive_reference) = &spec.hive {
        let product = "hive";
        let name = &hive_reference.name;
        let namespace = &hive_reference.namespace;

        hive_connect_string = client
            .get::<ConfigMap>(name, Some(namespace))
            .await
            .with_context(|| MissingConfigMap {
                name: name.clone(),
                namespace: namespace.clone(),
            })?
            .data
            .and_then(|mut data| data.remove(product))
            .with_context(|| MissingConnectString {
                product: product.to_string(),
                name: name.clone(),
                namespace: namespace.clone(),
            })?
            // TODO: hive now offers all pods fqdn(s) instead of the service
            //    this should be removed
            .split("\n")
            .collect::<Vec<_>>()
            .into_iter()
            .next()
            .map(|s| s.to_string());
    }

    Ok(hive_connect_string)
}

async fn extract_basic_auth_from_secret(
    client: &Client,
    basic_auth_secrets: &Option<Vec<SecretRef>>,
) -> Result<Vec<BasicAuthentication>> {
    let secrets = basic_auth_secrets.as_ref().context(MissingSecretInCrd)?;
    let mut collected_basic_auth = Vec::new();

    for secret in secrets {
        let name = &secret.name;
        let namespace = &secret
            .namespace
            .as_deref()
            .unwrap_or("<no-namespace>")
            .to_string();

        let secret = client
            .get::<Secret>(&name, secret.namespace.as_deref())
            .await
            .with_context(|| MissingSecret { name, namespace })?;

        let data = secret
            .data
            .with_context(|| MissingStringDataInSecret { name, namespace })?;

        let user_property = "username";
        let user_name = data
            .get(user_property)
            .with_context(|| MissingPropertyInSecretData {
                property: user_property.to_string(),
                name,
                namespace,
            })?;

        let password_property = "password";
        let password =
            data.get(password_property)
                .with_context(|| MissingPropertyInSecretData {
                    property: password_property.to_string(),
                    name,
                    namespace,
                })?;

        use std::str;

        // TODO: do not use unwrap!
        collected_basic_auth.push(BasicAuthentication {
            user: str::from_utf8(user_name.0.as_slice()).unwrap().to_string(),
            password: str::from_utf8(password.0.as_slice()).unwrap().to_string(),
        })
    }

    Ok(collected_basic_auth)
}

async fn tls_config_map_exists(trino: &TrinoCluster, client: &Client) -> Result<Option<String>> {
    if let Some(tls) = &trino.spec.tls {
        let name = tls.name.clone();
        let namespace = tls.namespace.as_deref();
        client
            .get::<ConfigMap>(&name, namespace)
            .await
            .with_context(|| MissingConfigMap {
                name: name.clone(),
                namespace: namespace.unwrap_or("<no-namespace>").to_string(),
            })?;
        return Ok(Some(name));
    }
    return Ok(None);
}
