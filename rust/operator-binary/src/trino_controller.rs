//! Ensures that `Pod`s are configured and running for each [`TrinoCluster`]

use std::{
    borrow::Cow,
    collections::{BTreeMap, HashMap},
    hash::Hasher,
    time::Duration,
};

use stackable_trino_crd::TrinoCluster;

use crate::{
    discovery::{self, build_discovery_configmaps},
    utils::{apply_owned, apply_status},
    APP_NAME, APP_PORT,
};
use fnv::FnvHasher;
use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::{
    builder::{ConfigMapBuilder, ContainerBuilder, ObjectMetaBuilder, PodBuilder},
    k8s_openapi::{
        api::{
            apps::v1::{StatefulSet, StatefulSetSpec},
            core::v1::{
                ConfigMap, ConfigMapVolumeSource, EnvVar, EnvVarSource, ExecAction,
                ObjectFieldSelector, PersistentVolumeClaim, PersistentVolumeClaimSpec, Probe,
                ResourceRequirements, Service, ServicePort, ServiceSpec, Volume,
            },
        },
        apimachinery::pkg::{api::resource::Quantity, apis::meta::v1::LabelSelector},
    },
    kube::{
        self,
        api::ObjectMeta,
        runtime::{
            controller::{Context, ReconcilerAction},
            reflector::ObjectRef,
        },
    },
    labels::{role_group_selector_labels, role_selector_labels},
    product_config::{
        types::PropertyNameKind, writer::to_java_properties_string, ProductConfigManager,
    },
    product_config_utils::{transform_all_roles_to_config, validate_all_roles_and_groups_config},
};
use stackable_trino_crd::{RoleGroupRef, TrinoRole};

const FIELD_MANAGER: &str = "trino.stackable.tech/trinocluster";

pub struct Ctx {
    pub kube: kube::Client,
    pub product_config: ProductConfigManager,
}

#[derive(Snafu, Debug)]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[snafu(display("object {} has no namespace", obj_ref))]
    ObjectHasNoNamespace {
        obj_ref: ObjectRef<TrinoCluster>,
    },
    #[snafu(display("object {} defines no version", obj_ref))]
    ObjectHasNoVersion {
        obj_ref: ObjectRef<TrinoCluster>,
    },
    #[snafu(display("{} has no server role", obj_ref))]
    NoServerRole {
        obj_ref: ObjectRef<TrinoCluster>,
    },
    #[snafu(display("failed to calculate global service name for {}", obj_ref))]
    GlobalServiceNameNotFound {
        obj_ref: ObjectRef<TrinoCluster>,
    },
    #[snafu(display("failed to calculate service name for role {}", rolegroup))]
    RoleGroupServiceNameNotFound { rolegroup: RoleGroupRef },
    #[snafu(display("failed to apply global Service for {}", trino))]
    ApplyRoleService {
        source: kube::Error,
        trino: ObjectRef<TrinoCluster>,
    },
    #[snafu(display("failed to apply Service for {}", rolegroup))]
    ApplyRoleGroupService {
        source: kube::Error,
        rolegroup: RoleGroupRef,
    },
    #[snafu(display("failed to build ConfigMap for {}", rolegroup))]
    BuildRoleGroupConfig {
        source: stackable_operator::error::Error,
        rolegroup: RoleGroupRef,
    },
    #[snafu(display("failed to apply ConfigMap for {}", rolegroup))]
    ApplyRoleGroupConfig {
        source: kube::Error,
        rolegroup: RoleGroupRef,
    },
    #[snafu(display("failed to apply StatefulSet for {}", rolegroup))]
    ApplyRoleGroupStatefulSet {
        source: kube::Error,
        rolegroup: RoleGroupRef,
    },
    #[snafu(display("invalid product config for {}", trino))]
    InvalidProductConfig {
        source: stackable_operator::error::Error,
        trino: ObjectRef<TrinoCluster>,
    },
    #[snafu(display("failed to serialize zoo.cfg for {}", rolegroup))]
    SerializeZooCfg {
        source: stackable_operator::product_config::writer::PropertiesWriterError,
        rolegroup: RoleGroupRef,
    },
    #[snafu(display("object {} is missing metadata to build owner reference", trino))]
    ObjectMissingMetadataForOwnerRef {
        source: stackable_operator::error::Error,
        trino: ObjectRef<TrinoCluster>,
    },
    #[snafu(display("failed to build discovery ConfigMap for {}", trino))]
    BuildDiscoveryConfig {
        source: discovery::Error,
        trino: ObjectRef<TrinoCluster>,
    },
    #[snafu(display("failed to apply discovery ConfigMap for {}", trino))]
    ApplyDiscoveryConfig {
        source: kube::Error,
        trino: ObjectRef<TrinoCluster>,
    },
    #[snafu(display("failed to update status of {}", trino))]
    ApplyStatus {
        source: kube::Error,
        trino: ObjectRef<TrinoCluster>,
    },
}
type Result<T, E = Error> = std::result::Result<T, E>;

const PROPERTIES_FILE: &str = "trino.cfg";

pub async fn reconcile_trino(trino: TrinoCluster, ctx: Context<Ctx>) -> Result<ReconcilerAction> {
    tracing::info!("Starting reconcile");
    let trino_ref = ObjectRef::from_obj(&trino);
    let kube = ctx.get_ref().kube.clone();

    let trino_version = trino
        .spec
        .version
        .as_deref()
        .with_context(|| ObjectHasNoVersion {
            obj_ref: trino_ref.clone(),
        })?;
    let validated_config = validate_all_roles_and_groups_config(
        trino_version,
        &transform_all_roles_to_config(
            &trino,
            [(
                TrinoRole::Coordinator.to_string(),
                TrinoRole::Worker.to_string(),
                (
                    vec![
                        PropertyNameKind::Env,
                        PropertyNameKind::File(PROPERTIES_FILE.to_string()),
                    ],
                    trino.spec.servers.clone().with_context(|| NoServerRole {
                        obj_ref: trino_ref.clone(),
                    })?,
                ),
            )]
            .into(),
        ),
        &ctx.get_ref().product_config,
        false,
        false,
    )
    .with_context(|| InvalidProductConfig { source: Error::ConfigMapMissingGenerateName, trino: trino_ref.clone() })?;
    let role_coordinator_config = validated_config
        .get(&TrinoRole::Coordinator.to_string())
        .map(Cow::Borrowed)
        .unwrap_or_default();

    let coordinator_role_service = apply_owned(&kube, FIELD_MANAGER, &build_coordinator_role_service(&trino)?)
        .await
        .with_context(|| ApplyRoleService { trino: trino_ref.clone() })?;

    for (rolegroup_name, rolegroup_config) in role_coordinator_config.iter() {
        let rolegroup = trino.coordinator_rolegroup_ref(rolegroup_name);

        apply_owned(
            &kube,
            FIELD_MANAGER,
            &build_coserver_rolegroup_service(&rolegroup, &trino)?,
        )
        .await
        .with_context(|| ApplyRoleGroupService {
            rolegroup: rolegroup.clone(),
        })?;
        apply_owned(
            &kube,
            FIELD_MANAGER,
            &build_server_rolegroup_config_map(&rolegroup, &trino, rolegroup_config)?,
        )
        .await
        .with_context(|| ApplyRoleGroupConfig {
            rolegroup: rolegroup.clone(),
        })?;
        apply_owned(
            &kube,
            FIELD_MANAGER,
            &build_server_rolegroup_statefulset(&rolegroup, &trino, rolegroup_config)?,
        )
        .await
        .with_context(|| ApplyRoleGroupStatefulSet {
            rolegroup: rolegroup.clone(),
        })?;
    }

    // std's SipHasher is deprecated, and DefaultHasher is unstable across Rust releases.
    // We don't /need/ stability, but it's still nice to avoid spurious changes where possible.
    let mut discovery_hash = FnvHasher::with_key(0);
    for discovery_cm in build_discovery_configmaps(&kube, &trino, &trino, &coordinator_role_service, None)
        .await
        .with_context(|| BuildDiscoveryConfig { trino: trino_ref.clone() })?
    {
        let discovery_cm = apply_owned(&kube, FIELD_MANAGER, &discovery_cm)
            .await
            .with_context(|| ApplyDiscoveryConfig { trino: trino_ref.clone() })?;
        if let Some(generation) = discovery_cm.metadata.resource_version {
            discovery_hash.write(generation.as_bytes())
        }
    }

    let status = TrinoClusterStatus {
        // Serialize as a string to discourage users from trying to parse the value,
        // and to keep things flexible if we end up changing the hasher at some point.
        discovery_hash: Some(discovery_hash.finish().to_string()),
    };
    apply_status(&kube, FIELD_MANAGER, &{
        let mut trino_with_status =
            TrinoCluster::new(&trino_ref.name, TrinoClusterSpec::default());
        trino_with_status.metadata.namespace = trino.metadata.namespace.clone();
        trino_with_status.status = Some(status);
        trino_with_status
    })
    .await
    .context(ApplyStatus { trino: trino_ref.clone() })?;

    Ok(ReconcilerAction {
        requeue_after: None,
    })
}

/// The server-role service is the primary endpoint that should be used by clients that do not perform internal load balancing,
/// including targets outside of the cluster.
///
/// Note that you should generally *not* hard-code clients to use these services; instead, create a [`ZookeeperZnode`](`stackable_zookeeper_crd::ZookeeperZnode`)
/// and use the connection string that it gives you.
pub fn build_coordinator_role_service(trino: &TrinoCluster) -> Result<Service> {
    let role_name = TrinoRole::Coordinator.to_string();
    let role_svc_name =
        trino.coordinator_role_service_name()
            .with_context(|| GlobalServiceNameNotFound {
                obj_ref: ObjectRef::from_obj(trino),
            })?;
    Ok(Service {
        metadata: ObjectMetaBuilder::new()
            .name_and_namespace(trino)
            .name(&role_svc_name)
            .ownerreference_from_resource(trino, None, Some(true))
            .with_context(|| ObjectMissingMetadataForOwnerRef {
                trino: ObjectRef::from_obj(trino),
            })?
            .with_recommended_labels(trino, APP_NAME, trino_version(trino)?, &role_name, "global")
            .build(),
        spec: Some(ServiceSpec {
            ports: Some(vec![ServicePort {
                name: Some("trino".to_string()),
                port: APP_PORT.into(),
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
fn build_coordinator_rolegroup_config_map(    rolegroup: &RoleGroupRef,    trino: &TrinoCluster,    coordinator_config: &HashMap<PropertyNameKind, BTreeMap<String, String>>,) -> Result<ConfigMap> {
    /*let mut zoo_cfg = coordinator_config
        .get(&PropertyNameKind::File(PROPERTIES_FILE.to_string()))
        .cloned()
        .unwrap_or_default();
    zoo_cfg.extend(zk.pods().into_iter().flatten().map(|pod| {
        (
            format!("server.{}", pod.zookeeper_myid),
            format!("{}:2888:3888;{}", pod.fqdn(), APP_PORT),
        )
    }));
    let zoo_cfg = zoo_cfg
        .into_iter()
        .map(|(k, v)| (k, Some(v)))
        .collect::<Vec<_>>();

     */

    ConfigMapBuilder::new()
        .metadata(
            ObjectMetaBuilder::new()
                .name_and_namespace(trino)
                .name(rolegroup.object_name())
                .ownerreference_from_resource(trino, None, Some(true))
                .with_context(|| ObjectMissingMetadataForOwnerRef {
                    trino: ObjectRef::from_obj(trino),
                })?
                .with_recommended_labels(
                    trino,
                    APP_NAME,
                    trino_version(trino)?,
                    &rolegroup.role,
                    &rolegroup.role_group,
                )
                .build(),
        )
        .add_data(
            "zoo.cfg", format!("test")
            /*to_java_properties_string(zoo_cfg.iter().map(|(k, v)| (k, v))).with_context(|| {
                SerializeZooCfg {
                    rolegroup: rolegroup.clone(),
                }
            })?,*/
        )
        .build()
        .with_context(|| BuildRoleGroupConfig {
            rolegroup: rolegroup.clone(),
        })
}

/// The rolegroup [`StatefulSet`] runs the rolegroup, as configured by the administrator.
///
/// The [`Pod`](`stackable_operator::k8s_openapi::api::core::v1::Pod`)s are accessible through the corresponding [`Service`] (from [`build_rolegroup_service`]).
fn build_coordinator_rolegroup_statefulset(
    rolegroup_ref: &RoleGroupRef,
    trino: &TrinoCluster,
    server_config: &HashMap<PropertyNameKind, BTreeMap<String, String>>,
) -> Result<StatefulSet> {
    let rolegroup = trino
        .spec
        .servers
        .as_ref()
        .with_context(|| NoServerRole {
            obj_ref: ObjectRef::from_obj(trino),
        })?
        .role_groups
        .get(&rolegroup_ref.role_group);
    let trino_version = trino_version(trino)?;
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
    let container_decide_myid = ContainerBuilder::new("decide-myid")
        .image(&image)
        .args(vec![
            "sh".to_string(),
            "-c".to_string(),
            "expr $MYID_OFFSET + $(echo $POD_NAME | sed 's/.*-//') > /stackable/data/myid"
                .to_string(),
        ])
        .add_env_vars(env.clone())
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
        .add_volume_mount("data", "/stackable/data")
        .build();
    let container_trino = ContainerBuilder::new("zookeeper")
        .image(image)
        .args(vec![
            "bin/zkServer.sh".to_string(),
            "start-foreground".to_string(),
            "/stackable/config/zoo.cfg".to_string(),
        ])
        .add_env_vars(env)
        // TODO: add a useful readiness probe
        //.add_container_port("zk", APP_PORT.into())
        .add_volume_mount("data", "/stackable/data")
        .add_volume_mount("config", "/stackable/config")
        .build();
    Ok(StatefulSet {
        metadata: ObjectMetaBuilder::new()
            .name_and_namespace(trino)
            .name(&rolegroup_ref.object_name())
            .ownerreference_from_resource(trino, None, Some(true))
            .with_context(|| ObjectMissingMetadataForOwnerRef {
                zk: ObjectRef::from_obj(trino),
            })?
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
                //.add_init_container(container_decide_myid)
                .add_container(container_trino)
                .add_volume(Volume {
                    name: "config".to_string(),
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
    trino.spec
        .version
        .as_deref()
        .with_context(|| ObjectHasNoVersion {
            obj_ref: ObjectRef::from_obj(trino),
        })
}

pub fn error_policy(_error: &Error, _ctx: Context<Ctx>) -> ReconcilerAction {
    ReconcilerAction {
        requeue_after: Some(Duration::from_secs(5)),
    }
}
