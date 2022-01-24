//! Ensures that `Pod`s are configured and running for each [`TrinoCluster`]
use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::client::Client;
use stackable_operator::k8s_openapi::api::core::v1::{
    CSIVolumeSource, ContainerPort, Probe, SecurityContext, TCPSocketAction,
};
use stackable_operator::k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use stackable_operator::kube::runtime::reflector::ObjectRef;
use stackable_operator::product_config_utils::ValidatedRoleConfigByPropertyKind;
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
use stackable_trino_crd::authentication::TrinoAuthenticationConfig;
use stackable_trino_crd::authorization::create_rego_rules;
use stackable_trino_crd::discovery::{TrinoDiscovery, TrinoDiscoveryProtocol, TrinoPodRef};
use stackable_trino_crd::{
    authentication, authorization, ClusterRef, TrinoCluster, TrinoClusterSpec, CONFIG_DIR_NAME,
    CONFIG_PROPERTIES, DATA_DIR_NAME, DISCOVERY_URI, HIVE_PROPERTIES, HTTPS_PORT, HTTPS_PORT_NAME,
    HTTP_PORT_NAME, JVM_CONFIG, KEYSTORE_DIR_NAME, LOG_PROPERTIES, METRICS_PORT, METRICS_PORT_NAME,
    NODE_PROPERTIES, PASSWORD_AUTHENTICATOR_PROPERTIES, PASSWORD_DB, USER_PASSWORD_DATA,
};
use stackable_trino_crd::{TrinoRole, APP_NAME, HTTP_PORT};
use std::str::FromStr;
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
    PropertiesWriteError {
        source: stackable_operator::product_config::writer::PropertiesWriterError,
    },
    #[snafu(display("Failed to load Product Config"))]
    ProductConfigLoadFailed,
    #[snafu(display("failed to create rego rules for authorization"))]
    RegoRuleAuthorizationError { source: authorization::Error },
    #[snafu(display("failed to get config map {}", config_map))]
    MissingConfigMap {
        source: stackable_operator::error::Error,
        config_map: ObjectRef<ConfigMap>,
    },
    #[snafu(display(
        "failed to get [{}] connection string from config map {}",
        product,
        config_map
    ))]
    MissingConnectString {
        product: String,
        config_map: ObjectRef<ConfigMap>,
    },
    #[snafu(display("failed to processing authentication config element from k8s"))]
    FailedProcessingAuthentication { source: authentication::Error },
    #[snafu(display("internal operator failure"))]
    InternalOperatorFailure { source: stackable_trino_crd::Error },
    #[snafu(display("no coordinator pods found for discovery"))]
    MissingCoordinatorPods,
}

type Result<T, E = Error> = std::result::Result<T, E>;

pub async fn reconcile_trino(trino: TrinoCluster, ctx: Context<Ctx>) -> Result<ReconcilerAction> {
    tracing::info!("Starting reconcile");

    let client = &ctx.get_ref().client;
    let version = trino_version(&trino)?;

    let validated_config =
        validated_product_config(&trino, version, &ctx.get_ref().product_config)?;

    // rego rules
    create_rego_rules(client, &trino)
        .await
        .context(RegoRuleAuthorizationSnafu)?;

    let coordinator_role_service = build_coordinator_role_service(&trino)?;
    client
        .apply_patch(
            FIELD_MANAGER_SCOPE,
            &coordinator_role_service,
            &coordinator_role_service,
        )
        .await
        .context(ApplyRoleServiceSnafu)?;

    let opa_connect = opa_connect(&trino, &ctx.get_ref().client).await?;
    let hive_connect = hive_connect(&trino, &ctx.get_ref().client).await?;

    let authentication_config = match &trino.spec.authentication {
        Some(authentication) => Some(
            authentication
                .method
                .materialize(client)
                .await
                .context(FailedProcessingAuthenticationSnafu)?,
        ),
        _ => None,
    };

    for (role, role_config) in validated_config {
        let trino_role = TrinoRole::from_str(&role).context(InternalOperatorFailureSnafu)?;
        for (role_group, config) in role_config {
            let rolegroup = trino_role.rolegroup_ref(&trino, role_group);
            let rg_service = build_rolegroup_service(&trino, &rolegroup)?;
            let rg_configmap =
                build_rolegroup_config_map(&trino, &trino_role, &rolegroup, &config, &opa_connect)?;
            let rg_catalog_configmap =
                build_rolegroup_catalog_config_map(&trino, &rolegroup, &config, &hive_connect)?;
            let rg_stateful_set = build_rolegroup_statefulset(
                &trino,
                &trino_role,
                &rolegroup,
                &config,
                &authentication_config,
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
        .context(GlobalServiceNameNotFoundSnafu)?;
    Ok(Service {
        metadata: ObjectMetaBuilder::new()
            .name_and_namespace(trino)
            .name(&role_svc_name)
            .ownerreference_from_resource(trino, None, Some(true))
            .context(ObjectMissingMetadataForOwnerRefSnafu)?
            .with_recommended_labels(trino, APP_NAME, trino_version(trino)?, &role_name, "global")
            .build(),
        spec: Some(ServiceSpec {
            ports: Some(service_ports()),
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
                        .context(PropertiesWriteSnafu)?;

                cm_conf_data.insert(file_name.to_string(), config_properties);
            }

            PropertyNameKind::File(file_name) if file_name == NODE_PROPERTIES => {
                let node_properties =
                    product_config::writer::to_java_properties_string(transformed_config.iter())
                        .context(PropertiesWriteSnafu)?;

                cm_conf_data.insert(file_name.to_string(), node_properties);
            }
            PropertyNameKind::File(file_name) if file_name == LOG_PROPERTIES => {
                let log_properties =
                    product_config::writer::to_java_properties_string(transformed_config.iter())
                        .context(PropertiesWriteSnafu)?;

                cm_conf_data.insert(file_name.to_string(), log_properties);
            }
            PropertyNameKind::File(file_name) if file_name == PASSWORD_AUTHENTICATOR_PROPERTIES => {
                let pw_properties =
                    product_config::writer::to_java_properties_string(transformed_config.iter())
                        .context(PropertiesWriteSnafu)?;
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
                .context(PropertiesWriteSnafu)?;

        cm_conf_data.insert("access-control.properties".to_string(), config_properties);
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
                    trino_version(trino)?,
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
                    .context(PropertiesWriteSnafu)?;

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
                    trino_version(trino)?,
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
    authentication_config: &Option<TrinoAuthenticationConfig>,
) -> Result<StatefulSet> {
    let rolegroup = role
        .get_spec(trino)
        .with_context(|| MissingTrinoRoleSnafu {
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

    let user_data = match authentication_config {
        Some(TrinoAuthenticationConfig::MultiUser { user_credentials }) => user_credentials
            .iter()
            .map(|(user, password)| format!("{}:{}", user, password))
            .collect::<Vec<_>>()
            .join("\n"),
        None => String::new(),
    };

    let mut container_prepare = ContainerBuilder::new("prepare")
        .image(&image)
        .command(vec!["/bin/bash".to_string(), "-c".to_string()])
        .args(vec![[
            "microdnf install openssl",
            "echo Storing password",
            "echo secret > /stackable/keystore/password",
            "echo Creating truststore",
            "keytool -importcert -file /stackable/keystore/ca.crt -keystore /stackable/keystore/truststore.p12 -storetype pkcs12 -noprompt -alias ca_cert -storepass secret",
            "echo Creating certificate chain",
            "cat /stackable/keystore/ca.crt /stackable/keystore/tls.crt > /stackable/keystore/chain.crt",
            "echo Creating keystore",
            "openssl pkcs12 -export -in /stackable/keystore/chain.crt -inkey /stackable/keystore/tls.key -out /stackable/keystore/keystore.p12 --passout file:/stackable/keystore/password",
            "echo Cleaning up password",
            "rm -f /stackable/keystore/password",
            "echo chowning keystore directory",
            "chown -R stackable:stackable /stackable/keystore",
            "echo chmodding keystore directory",
            "chmod -R a=,u=rwX /stackable/keystore",
        ].join(" && ")])
        .add_volume_mount("keystore", "/stackable/keystore")
        .build();

    container_prepare
        .security_context
        .get_or_insert_with(SecurityContext::default)
        .run_as_user = Some(0);

    let container_trino = ContainerBuilder::new(APP_NAME)
        .image(image)
        .command(vec!["/bin/bash".to_string(), "-c".to_string()])
        .args(vec![[
            format!(
                "echo Writing user data to {}/{}",
                USER_PASSWORD_DATA, PASSWORD_DB
            ),
            format!("mkdir {}", USER_PASSWORD_DATA),
            format!(
                "echo '{}' > {}/{} ",
                user_data, USER_PASSWORD_DATA, PASSWORD_DB
            ),
            format!("bin/launcher run --etc-dir={}", CONFIG_DIR_NAME),
        ]
        .join(" && ")])
        .add_env_vars(env)
        .add_volume_mount("data", DATA_DIR_NAME)
        .add_volume_mount("conf", CONFIG_DIR_NAME)
        .add_volume_mount("keystore", KEYSTORE_DIR_NAME)
        .add_volume_mount("catalog", format!("{}/catalog", CONFIG_DIR_NAME))
        .add_container_ports(container_ports())
        .readiness_probe(Probe {
            initial_delay_seconds: Some(10),
            period_seconds: Some(10),
            failure_threshold: Some(5),
            tcp_socket: Some(TCPSocketAction {
                port: IntOrString::String(HTTPS_PORT_NAME.to_string()),
                ..TCPSocketAction::default()
            }),
            ..Probe::default()
        })
        .liveness_probe(Probe {
            initial_delay_seconds: Some(30),
            period_seconds: Some(10),
            tcp_socket: Some(TCPSocketAction {
                port: IntOrString::String(HTTPS_PORT_NAME.to_string()),
                ..TCPSocketAction::default()
            }),
            ..Probe::default()
        })
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
                .add_init_container(container_prepare)
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
                    name: "keystore".to_string(),
                    csi: Some(CSIVolumeSource {
                        driver: "secrets.stackable.tech".to_string(),
                        volume_attributes: Some(get_stackable_secret_volume_attributes()),
                        ..CSIVolumeSource::default()
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
            .context(ObjectMissingMetadataForOwnerRefSnafu)?
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
            ports: Some(service_ports()),
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
    trino
        .spec
        .version
        .as_deref()
        .context(ObjectHasNoVersionSnafu)
}

/// Returns the "real" Trino version for docker images e.g. 362
pub fn trino_version_trim(trino: &TrinoCluster) -> Result<&str> {
    let spec: &TrinoClusterSpec = &trino.spec;
    spec.version
        .as_deref()
        .and_then(|v| v.split('.').collect::<Vec<_>>().last().cloned())
        .context(ObjectHasNoVersionSnafu)
}

pub fn error_policy(_error: &Error, _ctx: Context<Ctx>) -> ReconcilerAction {
    ReconcilerAction {
        requeue_after: Some(Duration::from_secs(5)),
    }
}

async fn opa_connect(trino: &TrinoCluster, client: &Client) -> Result<Option<String>> {
    let mut opa_connect_string = None;

    if let Some(opa_reference) = &trino.spec.opa {
        let product = "OPA";
        opa_connect_string = Some(cluster_ref_cm_data(client, opa_reference, product).await?);
    }

    Ok(opa_connect_string)
}

async fn hive_connect(trino: &TrinoCluster, client: &Client) -> Result<Option<String>> {
    let mut hive_connect_string = None;

    if let Some(hive_reference) = &trino.spec.hive {
        let product = "hive";

        hive_connect_string = cluster_ref_cm_data(client, hive_reference, product)
            .await?
            // TODO: hive now offers all pods fqdn(s) instead of the service
            //    this should be removed
            .split('\n')
            .collect::<Vec<_>>()
            .into_iter()
            .next()
            .map(|s| s.to_string());
    }

    Ok(hive_connect_string)
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

async fn cluster_ref_cm_data(
    client: &Client,
    cluster_ref: &ClusterRef,
    product_name: &str,
) -> Result<String> {
    let name = &cluster_ref.name;
    let namespace = &cluster_ref.namespace;

    Ok(client
        .get::<ConfigMap>(name, Some(namespace))
        .await
        .with_context(|_| MissingConfigMapSnafu {
            config_map: ObjectRef::new(name).within(namespace),
        })?
        .data
        .and_then(|mut data| data.remove(product_name))
        .with_context(|| MissingConnectStringSnafu {
            product: product_name.to_string(),
            config_map: ObjectRef::new(name).within(namespace),
        })?)
}

fn service_ports() -> Vec<ServicePort> {
    vec![
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
    ]
}

fn container_ports() -> Vec<ContainerPort> {
    vec![
        ContainerPort {
            name: Some(HTTP_PORT_NAME.to_string()),
            container_port: HTTP_PORT.into(),
            protocol: Some("TCP".to_string()),
            ..ContainerPort::default()
        },
        ContainerPort {
            name: Some(HTTPS_PORT_NAME.to_string()),
            container_port: HTTPS_PORT.into(),
            protocol: Some("TCP".to_string()),
            ..ContainerPort::default()
        },
        ContainerPort {
            name: Some(METRICS_PORT_NAME.to_string()),
            container_port: METRICS_PORT.into(),
            protocol: Some("TCP".to_string()),
            ..ContainerPort::default()
        },
    ]
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
