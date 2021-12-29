//! Ensures that `Pod`s are configured and running for each [`TrinoCluster`]
use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::role_utils::{Role, RoleGroupRef};
use stackable_operator::{
    builder::{ConfigMapBuilder, ContainerBuilder, ObjectMetaBuilder, PodBuilder},
    k8s_openapi::{
        api::{
            apps::v1::{StatefulSet, StatefulSetSpec},
            core::v1::{
                ConfigMap, ConfigMapVolumeSource, EnvVar, EnvVarSource, ObjectFieldSelector,
                PersistentVolumeClaim, PersistentVolumeClaimSpec, ResourceRequirements, Service,
                ServicePort, ServiceSpec, Volume,
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
use stackable_trino_crd::discovery::{TrinoDiscovery, TrinoDiscoveryProtocol, TrinoPodRef};
use stackable_trino_crd::{
    TrinoCluster, TrinoConfig, CERTIFICATE_PEM, CERT_FILE_CONTENT_MAP_KEY, CONFIG_DIR_NAME,
    CONFIG_PROPERTIES, DATA_DIR_NAME, DISCOVERY_URI, HIVE_PROPERTIES, JVM_CONFIG, LOG_PROPERTIES,
    METRICS_PORT, NODE_ID, NODE_PROPERTIES, PASSWORD_AUTHENTICATOR_PROPERTIES, PASSWORD_DB,
    PW_FILE_CONTENT_MAP_KEY,
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
    #[snafu(display("Failed to transform configs"))]
    ProductConfigTransform {
        source: stackable_operator::product_config_utils::ConfigError,
    },
    #[snafu(display("Failed to format runtime properties"))]
    PropertiesWriteError {
        source: stackable_operator::product_config::writer::PropertiesWriterError,
    },
}
type Result<T, E = Error> = std::result::Result<T, E>;

pub async fn reconcile_trino(trino: TrinoCluster, ctx: Context<Ctx>) -> Result<ReconcilerAction> {
    tracing::info!("Starting reconcile");

    let client = &ctx.get_ref().client;
    let version = trino_version(&trino)?;
    let roles = create_roles(&trino)?;

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

    for (role, role_config) in validated_config {
        let trino_role = TrinoRole::from(role);
        for (role_group, config) in role_config {
            let rolegroup = trino.coordinator_rolegroup_ref(role_group);

            let rg_service = build_rolegroup_service(&trino, &rolegroup)?;
            let rg_configmap =
                build_rolegroup_config_map(&trino, &trino_role, &rolegroup, &config)?;
            let rg_stateful_set = build_rolegroup_statefulset(&trino, &rolegroup, &config)?;

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
                .apply_patch(FIELD_MANAGER_SCOPE, &rg_stateful_set, &rg_stateful_set)
                .await
                .with_context(|| ApplyRoleGroupStatefulSet {
                    rolegroup: rolegroup.clone(),
                })?;

            break;
        }
        break;
    }

    Ok(ReconcilerAction {
        requeue_after: None,
    })
}

/// The server-role service is the primary endpoint that should be used by clients that do not
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
            ports: Some(vec![ServicePort {
                name: Some("trino".to_string()),
                port: HTTP_PORT.into(),
                protocol: Some("TCP".to_string()),
                ..ServicePort::default()
            }]),
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
    role: &TrinoRole,
    rolegroup: &RoleGroupRef<TrinoCluster>,
    coordinator_config: &HashMap<PropertyNameKind, BTreeMap<String, String>>,
) -> Result<ConfigMap> {
    let mut cm_conf_data = BTreeMap::new();
    //let mut cm_hive_data = BTreeMap::new();

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

    for (property_name_kind, config) in coordinator_config {
        let mut transformed_config: BTreeMap<String, Option<String>> = config
            .iter()
            .map(|(k, v)| (k.clone(), Some(v.clone())))
            .collect();

        match property_name_kind {
            PropertyNameKind::File(file_name) if file_name == CONFIG_PROPERTIES => {
                // TODO: make http / https configurable
                let discovery =
                    TrinoDiscovery::new(&coordinator_ref, TrinoDiscoveryProtocol::Https);
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
                // we have to generate a unique node.id which consists of <role>-<id>.
                // TODO: This must be replaced via sed before running trino
                transformed_config.insert(
                    NODE_ID.to_string(),
                    //Some(format!("{}-{}", pod_id.role(), pod_id.id())),
                    //Some("".to_string()),
                    Some("12345".to_string()),
                );

                let node_properties =
                    product_config::writer::to_java_properties_string(transformed_config.iter())
                        .context(PropertiesWriteError)?;

                cm_conf_data.insert(file_name.to_string(), node_properties);
            }
            PropertyNameKind::File(file_name) if file_name == HIVE_PROPERTIES => {
                // if let Some(hive_info) = &trino.spec.hive_information {
                //     transformed_config
                //         .insert("connector.name".to_string(), Some("hive".to_string()));
                //     transformed_config.insert(
                //         "hive.metastore.uri".to_string(),
                //         Some(hive_info.full_connection_string()),
                //     );
                //
                //     let config_properties = product_config::writer::to_java_properties_string(
                //         transformed_config.iter(),
                //     )?;
                //
                //     cm_hive_data.insert(HIVE_PROPERTIES.to_string(), config_properties);
                // }
            }
            PropertyNameKind::File(file_name) if file_name == LOG_PROPERTIES => {
                let log_properties =
                    product_config::writer::to_java_properties_string(transformed_config.iter())
                        .context(PropertiesWriteError)?;

                cm_conf_data.insert(file_name.to_string(), log_properties);
            }
            PropertyNameKind::File(file_name) if file_name == PASSWORD_AUTHENTICATOR_PROPERTIES => {
                if role == &TrinoRole::Coordinator && !transformed_config.is_empty() {
                    let pw_properties = product_config::writer::to_java_properties_string(
                        transformed_config.iter(),
                    )
                    .context(PropertiesWriteError)?;
                    cm_conf_data.insert(file_name.to_string(), pw_properties);
                }
            }
            PropertyNameKind::File(file_name) if file_name == PASSWORD_DB => {
                if role == &TrinoRole::Coordinator && !config.is_empty() {
                    if let Some(pw_file_content) = config.get(PW_FILE_CONTENT_MAP_KEY) {
                        cm_conf_data.insert(file_name.to_string(), pw_file_content.to_string());
                    }
                }
            }
            PropertyNameKind::File(file_name) if file_name == JVM_CONFIG => {
                jvm_config.push_str(&format!("\n-javaagent:/stackable/jmx/jmx_prometheus_javaagent-0.16.1.jar={}:/stackable/jmx/config.yaml", METRICS_PORT));
            }
            PropertyNameKind::File(file_name) if file_name == CERTIFICATE_PEM => {
                if role == &TrinoRole::Coordinator && !config.is_empty() {
                    if let Some(cert_file_content) = config.get(CERT_FILE_CONTENT_MAP_KEY) {
                        cm_conf_data.insert(file_name.to_string(), cert_file_content.to_string());
                    }
                }
            }
            _ => {}
        }
    }

    cm_conf_data.insert(JVM_CONFIG.to_string(), jvm_config.to_string());

    ConfigMapBuilder::new()
        .metadata(
            ObjectMetaBuilder::new()
                .name_and_namespace(trino)
                .name(rolegroup.object_name())
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
        )
        .data(cm_conf_data)
        .build()
        .with_context(|| BuildRoleGroupConfig {
            rolegroup: rolegroup.clone(),
        })
}

/// The rolegroup [`StatefulSet`] runs the rolegroup, as configured by the administrator.
///
/// The [`Pod`](`stackable_operator::k8s_openapi::api::core::v1::Pod`)s are accessible through the
/// corresponding [`Service`] (from [`build_rolegroup_service`]).
fn build_rolegroup_statefulset(
    trino: &TrinoCluster,
    rolegroup_ref: &RoleGroupRef<TrinoCluster>,
    server_config: &HashMap<PropertyNameKind, BTreeMap<String, String>>,
) -> Result<StatefulSet> {
    let rolegroup = trino
        .spec
        .coordinators
        .as_ref()
        .with_context(|| MissingTrinoRole {
            role: TrinoRole::Coordinator.to_string(),
        })?
        .role_groups
        .get(&rolegroup_ref.role_group);
    // TODO: do not hardcode
    let trino_version = "362"; //trino_version(trino)?;
    let image = format!(
        "docker.stackable.tech/stackable/trino:{}-stackable0",
        trino_version
    );
    let env = server_config
        .get(&PropertyNameKind::Env)
        .iter()
        .flat_map(|env_vars| env_vars.iter())
        .map(|(k, v)| EnvVar {
            name: k.clone(),
            value: Some(v.clone()),
            ..EnvVar::default()
        })
        .collect::<Vec<_>>();
    let node_address = format!(
        "$POD_NAME.{}-node-{}.default.svc.cluster.local",
        rolegroup_ref.cluster.name, rolegroup_ref.role_group
    );
    let container_trino = ContainerBuilder::new(APP_NAME)
        .image(image)
        .command(vec!["/bin/bash".to_string(), "-c".to_string()])
        .args(vec![format!(
            "sed -i \"s/{}=/{}={}/g\" {}/config.properties;
             bin/launcher run --etc-dir={}",
            DISCOVERY_URI, DISCOVERY_URI, node_address, CONFIG_DIR_NAME, CONFIG_DIR_NAME
        )])
        .add_env_vars(env)
        .add_volume_mount("data", DATA_DIR_NAME)
        .add_volume_mount("conf", CONFIG_DIR_NAME)
        .add_env_vars(vec![EnvVar {
            name: "POD_NAME".to_string(),
            value_from: Some(EnvVarSource {
                field_ref: Some(ObjectFieldSelector {
                    api_version: Some("v1".to_string()),
                    field_path: "metadata.name".to_string(),
                }),
                ..EnvVarSource::default()
            }),
            ..EnvVar::default()
        }])
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
            ports: Some(vec![ServicePort {
                name: Some("trino".to_string()),
                port: HTTP_PORT.into(),
                protocol: Some("TCP".to_string()),
                ..ServicePort::default()
            }]),
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

/*
pub fn build_worker_role_service(trino: &TrinoCluster) -> Result<Service> {
    let role_name = TrinoRole::Worker.to_string();
    let role_svc_name =
        zk.server_role_service_name()
            .with_context(|| GlobalServiceNameNotFound {
                obj_ref: ObjectRef::from_obj(zk),
            })?;
    Ok(Service {
        metadata: ObjectMetaBuilder::new()
            .name_and_namespace(zk)
            .name(&role_svc_name)
            .ownerreference_from_resource(zk, None, Some(true))
            .with_context(|| ObjectMissingMetadataForOwnerRef {
                zk: ObjectRef::from_obj(zk),
            })?
            .with_recommended_labels(zk, APP_NAME, trino_version(zk)?, &role_name, "global")
            .build(),
        spec: Some(ServiceSpec {
            ports: Some(vec![ServicePort {
                name: Some("zk".to_string()),
                port: APP_PORT.into(),
                protocol: Some("TCP".to_string()),
                ..ServicePort::default()
            }]),
            selector: Some(role_selector_labels(zk, APP_NAME, &role_name)),
            type_: Some("NodePort".to_string()),
            ..ServiceSpec::default()
        }),
        status: None,
    })
}


/// The rolegroup [`Service`] is a headless service that allows direct access to the instances of a certain rolegroup
///
/// This is mostly useful for internal communication between peers, or for clients that perform client-side load balancing.
fn build_worker_rolegroup_service(
    rolegroup: &RoleGroupRef,
    zk: &TrinoCluster,
) -> Result<Service> {
    Ok(Service {
        metadata: ObjectMetaBuilder::new()
            .name_and_namespace(zk)
            .name(&rolegroup.object_name())
            .ownerreference_from_resource(zk, None, Some(true))
            .with_context(|| ObjectMissingMetadataForOwnerRef {
                zk: ObjectRef::from_obj(zk),
            })?
            .with_recommended_labels(
                zk,
                APP_NAME,
                trino_version(zk)?,
                &rolegroup.role,
                &rolegroup.role_group,
            )
            .build(),
        spec: Some(ServiceSpec {
            cluster_ip: Some("None".to_string()),
            ports: Some(vec![
                ServicePort {
                    name: Some("zk".to_string()),
                    port: APP_PORT.into(),
                    protocol: Some("TCP".to_string()),
                    ..ServicePort::default()
                },
                ServicePort {
                    name: Some("metrics".to_string()),
                    port: 9505,
                    protocol: Some("TCP".to_string()),
                    ..ServicePort::default()
                },
            ]),
            selector: Some(role_group_selector_labels(
                zk,
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

TODO: add worker statefulset fn
*/

pub fn trino_version(trino: &TrinoCluster) -> Result<&str> {
    trino.spec.version.as_deref().context(ObjectHasNoVersion)
}

pub fn error_policy(_error: &Error, _ctx: Context<Ctx>) -> ReconcilerAction {
    ReconcilerAction {
        requeue_after: Some(Duration::from_secs(5)),
    }
}

fn create_roles(
    trino: &TrinoCluster,
) -> Result<HashMap<String, (Vec<PropertyNameKind>, Role<TrinoConfig>)>> {
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
                    PropertyNameKind::File(CERTIFICATE_PEM.to_string()),
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

    Ok(roles)
}
