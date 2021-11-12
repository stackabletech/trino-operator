mod error;

use crate::error::Error;

use async_trait::async_trait;
use stackable_hive_crd::discovery::HiveConnectionInformation;
use stackable_opa_crd::util;
use stackable_opa_crd::util::{OpaApi, OpaApiProtocol};
use stackable_operator::builder::{ContainerBuilder, ObjectMetaBuilder, PodBuilder, VolumeBuilder};
use stackable_operator::client::Client;
use stackable_operator::command::materialize_command;
use stackable_operator::controller::Controller;
use stackable_operator::controller::{ControllerStrategy, ReconciliationState};
use stackable_operator::error::OperatorResult;
use stackable_operator::identity::{LabeledPodIdentityFactory, PodIdentity, PodToNodeMapping};
use stackable_operator::k8s_openapi::api::core::v1::{ConfigMap, Pod};
use stackable_operator::kube::api::{ListParams, ResourceExt};
use stackable_operator::kube::Api;
use stackable_operator::labels;
use stackable_operator::labels::{
    build_common_labels_for_all_managed_resources, get_recommended_labels,
};
use stackable_operator::name_utils;
use stackable_operator::product_config::types::PropertyNameKind;
use stackable_operator::product_config::ProductConfigManager;
use stackable_operator::product_config_utils::{
    config_for_role_and_group, transform_all_roles_to_config, validate_all_roles_and_groups_config,
    ValidatedRoleConfigByPropertyKind,
};
use stackable_operator::reconcile::{
    ContinuationStrategy, ReconcileFunctionAction, ReconcileResult, ReconciliationContext,
};
use stackable_operator::role_utils;
use stackable_operator::role_utils::{
    get_role_and_group_labels, list_eligible_nodes_for_role_and_group, EligibleNodesForRoleAndGroup,
};
use stackable_operator::scheduler::{
    K8SUnboundedHistory, RoleGroupEligibleNodes, ScheduleStrategy, Scheduler, StickyScheduler,
};
use stackable_operator::status::HasClusterExecutionStatus;
use stackable_operator::status::{init_status, ClusterExecutionStatus};
use stackable_operator::versioning::{finalize_versioning, init_versioning};
use stackable_operator::{configmap, product_config};
use stackable_trino_crd::commands::{Restart, Start, Stop};
use stackable_trino_crd::discovery::{
    get_trino_discovery_from_pods, TrinoDiscovery, TrinoDiscoveryProtocol,
};
use stackable_trino_crd::{
    TrinoCluster, TrinoClusterSpec, TrinoRole, APP_NAME, CERTIFICATE_PEM,
    CERT_FILE_CONTENT_MAP_KEY, CONFIG_DIR_NAME, CONFIG_PROPERTIES, DISCOVERY_URI, HIVE_PROPERTIES,
    HTTPS_PORT, HTTP_PORT, HTTP_SERVER_HTTPS_PORT, HTTP_SERVER_HTTP_PORT, JVM_CONFIG,
    LOG_PROPERTIES, METRICS_PORT, METRICS_PORT_PROPERTY, NODE_ID, NODE_PROPERTIES,
    PASSWORD_AUTHENTICATOR_PROPERTIES, PASSWORD_DB, PW_FILE_CONTENT_MAP_KEY,
};
use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use strum::IntoEnumIterator;
use tracing::{debug, error, info, trace, warn};

/// The docker image we default to. This needs to be adapted if the operator does not work
/// with images 0.0.1, 0.1.0 etc. anymore and requires e.g. a new major version like 1(.0.0).
const DEFAULT_IMAGE_VERSION: &str = "0";

const FINALIZER_NAME: &str = "trino.stackable.tech/cleanup";
const ID_LABEL: &str = "trino.stackable.tech/id";
const SHOULD_BE_SCRAPED: &str = "monitoring.stackable.tech/should_be_scraped";

const CONFIG_MAP_TYPE_CONF: &str = "config";
const CONFIG_MAP_TYPE_HIVE: &str = "hive";

type TrinoReconcileResult = ReconcileResult<error::Error>;

struct TrinoState {
    context: ReconciliationContext<TrinoCluster>,
    existing_pods: Vec<Pod>,
    eligible_nodes: EligibleNodesForRoleAndGroup,
    validated_role_config: ValidatedRoleConfigByPropertyKind,
    trino_discovery: Option<TrinoDiscovery>,
    hive_information: Option<HiveConnectionInformation>,
}

impl TrinoState {
    async fn get_trino_discovery(&mut self) -> TrinoReconcileResult {
        let discovery = get_trino_discovery_from_pods(&self.existing_pods)?;

        debug!("Received Trino discovery information: [{:?}]", discovery);

        self.trino_discovery = discovery;

        Ok(ReconcileFunctionAction::Continue)
    }

    async fn get_hive_connection_information(&mut self) -> TrinoReconcileResult {
        let hive_ref: &stackable_hive_crd::discovery::HiveReference =
            &self.context.resource.spec.hive_reference;

        let hive_info =
            stackable_hive_crd::discovery::get_hive_connection_info(&self.context.client, hive_ref)
                .await?;

        debug!("Received Hive connection information: [{:?}]", hive_info);

        self.hive_information = hive_info;

        Ok(ReconcileFunctionAction::Continue)
    }

    async fn create_rego_rules(&self) -> TrinoReconcileResult {
        let spec: &TrinoClusterSpec = &self.context.resource.spec;
        if let Some(authorization) = &spec.authorization {
            let rego_rules = stackable_trino_crd::authorization::build_rego_rules(authorization);

            stackable_trino_crd::authorization::create_or_update_rego_rule_resource(
                &self.context.client,
                &authorization.package,
                rego_rules,
            )
            .await?;
        }
        Ok(ReconcileFunctionAction::Continue)
    }

    /// Required labels for pods. Pods without any of these will deleted and/or replaced.
    pub fn get_required_labels(&self) -> BTreeMap<String, Option<Vec<String>>> {
        let roles = TrinoRole::iter()
            .map(|role| role.to_string())
            .collect::<Vec<_>>();
        let mut mandatory_labels = BTreeMap::new();

        mandatory_labels.insert(labels::APP_COMPONENT_LABEL.to_string(), Some(roles));
        mandatory_labels.insert(
            labels::APP_INSTANCE_LABEL.to_string(),
            Some(vec![self.context.name()]),
        );
        mandatory_labels.insert(
            labels::APP_VERSION_LABEL.to_string(),
            Some(vec![self.context.resource.spec.version.to_string()]),
        );
        mandatory_labels.insert(ID_LABEL.to_string(), None);

        mandatory_labels
    }

    /// Will initialize the status object if it's never been set.
    async fn init_status(&mut self) -> TrinoReconcileResult {
        // init status with default values if not available yet.
        self.context.resource = init_status(&self.context.client, &self.context.resource).await?;

        let spec_version = self.context.resource.spec.version.clone();

        self.context.resource =
            init_versioning(&self.context.client, &self.context.resource, spec_version).await?;

        // set the cluster status to running
        if self.context.resource.cluster_execution_status().is_none() {
            self.context
                .client
                .merge_patch_status(
                    &self.context.resource,
                    &self
                        .context
                        .resource
                        .cluster_execution_status_patch(&ClusterExecutionStatus::Running),
                )
                .await?;
        }

        Ok(ReconcileFunctionAction::Continue)
    }

    pub async fn create_missing_pods(&mut self) -> TrinoReconcileResult {
        trace!(target: "create_missing_pods","Starting `create_missing_pods`");

        // The iteration happens in two stages here, to accommodate the way our operators think
        // about roles and role groups.
        // The hierarchy is:
        // - Roles (Coordinator, Worker)
        //   - Role groups (user defined)
        for role in TrinoRole::iter() {
            let role_str = &role.to_string();
            if let Some(nodes_for_role) = self.eligible_nodes.get(role_str) {
                for (role_group, eligible_nodes) in nodes_for_role {
                    debug!( target: "create_missing_pods",
                        "Identify missing pods for [{}] role and group [{}]",
                        role_str, role_group
                    );
                    trace!( target: "create_missing_pods",
                        "candidate_nodes[{}]: [{:?}]",
                        eligible_nodes.nodes.len(),
                        eligible_nodes
                            .nodes
                            .iter()
                            .map(|node| node.metadata.name.as_ref().unwrap())
                            .collect::<Vec<_>>()
                    );
                    trace!(target: "create_missing_pods",
                        "existing_pods[{}]: [{:?}]",
                        &self.existing_pods.len(),
                        &self
                            .existing_pods
                            .iter()
                            .map(|pod| pod.metadata.name.as_ref().unwrap())
                            .collect::<Vec<_>>()
                    );
                    trace!(target: "create_missing_pods",
                        "labels: [{:?}]",
                        get_role_and_group_labels(role_str, role_group)
                    );
                    let mut history = match self
                        .context
                        .resource
                        .status
                        .as_ref()
                        .and_then(|status| status.history.as_ref())
                    {
                        Some(simple_history) => {
                            // we clone here because we cannot access mut self because we need it later
                            // to create config maps and pods. The `status` history will be out of sync
                            // with the cloned `simple_history` until the next reconcile.
                            // The `status` history should not be used after this method to avoid side
                            // effects.
                            K8SUnboundedHistory::new(&self.context.client, simple_history.clone())
                        }
                        None => K8SUnboundedHistory::new(
                            &self.context.client,
                            PodToNodeMapping::default(),
                        ),
                    };

                    let mut sticky_scheduler =
                        StickyScheduler::new(&mut history, ScheduleStrategy::GroupAntiAffinity);

                    let pod_id_factory = LabeledPodIdentityFactory::new(
                        APP_NAME,
                        &self.context.name(),
                        &self.eligible_nodes,
                        ID_LABEL,
                        1,
                    );

                    trace!("pod_id_factory: {:?}", pod_id_factory.as_ref());

                    let state = sticky_scheduler.schedule(
                        &pod_id_factory,
                        &RoleGroupEligibleNodes::from(&self.eligible_nodes),
                        &self.existing_pods,
                    )?;

                    let mapping = state.remaining_mapping().filter(
                        APP_NAME,
                        &self.context.name(),
                        role_str,
                        role_group,
                    );

                    if let Some((pod_id, node_id)) = mapping.iter().next() {
                        // now we have a node that needs a pod -> get validated config
                        let validated_config = config_for_role_and_group(
                            pod_id.role(),
                            pod_id.group(),
                            &self.validated_role_config,
                        )?;

                        let config_maps = self
                            .create_config_maps(pod_id, &role, &node_id.name, validated_config)
                            .await?;

                        self.create_pod(
                            pod_id,
                            &role,
                            &node_id.name,
                            &config_maps,
                            validated_config,
                        )
                        .await?;

                        history.save(&self.context.resource).await?;

                        return Ok(ReconcileFunctionAction::Requeue(Duration::from_secs(10)));
                    }
                }
            }
        }

        // If we reach here it means all pods must be running on target_version.
        // We can now set current_version to target_version (if target_version was set) and
        // target_version to None
        finalize_versioning(&self.context.client, &self.context.resource).await?;

        Ok(ReconcileFunctionAction::Continue)
    }

    /// Creates the config maps required for a Trino instance (or role, role_group combination):
    /// * The 'node.properties'
    /// * The 'config.properties'
    /// * The 'jvm.config'
    /// * The 'log.properties'
    ///
    /// Returns a map with a 'type' identifier (e.g. config) as key and the corresponding
    /// ConfigMap as value. This is required to set the volume mounts in the pod later on.
    ///
    /// # Arguments
    ///
    /// - `pod_id` - The `PodIdentity` containing app, instance, role, group names and the id.
    /// - `role` - The `TrinoRole` for the pod to be created.
    /// - `node_name` - The node_name where the pod will be scheduled.
    /// - `validated_config` - The validated product config.
    /// - `id_mapping` - All id to node mappings required to create config maps
    ///
    async fn create_config_maps(
        &self,
        pod_id: &PodIdentity,
        role: &TrinoRole,
        node_name: &str,
        validated_config: &HashMap<PropertyNameKind, BTreeMap<String, String>>,
    ) -> Result<HashMap<&'static str, ConfigMap>, Error> {
        let mut config_maps = HashMap::new();
        let mut cm_conf_data = BTreeMap::new();
        let mut cm_hive_data = BTreeMap::new();

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

        for (property_name_kind, config) in validated_config {
            let mut transformed_config: BTreeMap<String, Option<String>> = config
                .iter()
                .map(|(k, v)| (k.clone(), Some(v.clone())))
                .collect();

            match property_name_kind {
                PropertyNameKind::File(file_name) if file_name == CONFIG_PROPERTIES => {
                    // if we a coordinator, we need to build the discovery string; workers can
                    // use the discovery service once a coordinator was created
                    if role == &TrinoRole::Coordinator {
                        if let Some(http_port) = config.get(HTTP_SERVER_HTTP_PORT) {
                            let build_discovery = TrinoDiscovery {
                                node_name: node_name.to_string(),
                                http_port: http_port.clone(),
                                // TODO: what with https?
                                protocol: TrinoDiscoveryProtocol::default(),
                            };
                            transformed_config.insert(
                                DISCOVERY_URI.to_string(),
                                Some(build_discovery.connection_string()),
                            );
                        } else {
                            return Err(Error::TrinoCoordinatorMissingPortError {
                                port: HTTP_SERVER_HTTP_PORT.to_string(),
                                discovery_property: DISCOVERY_URI.to_string(),
                            });
                        }
                    } else if role == &TrinoRole::Worker {
                        if let Some(discovery) = &self.trino_discovery {
                            transformed_config.insert(
                                DISCOVERY_URI.to_string(),
                                Some(discovery.connection_string()),
                            );
                        }
                    }

                    let config_properties = product_config::writer::to_java_properties_string(
                        transformed_config.iter(),
                    )?;

                    cm_conf_data.insert(file_name.to_string(), config_properties);
                }

                PropertyNameKind::File(file_name) if file_name == NODE_PROPERTIES => {
                    // we have to generate a unique node.id which consists of <role>-<id>.
                    transformed_config.insert(
                        NODE_ID.to_string(),
                        Some(format!("{}-{}", pod_id.role(), pod_id.id())),
                    );

                    let node_properties = product_config::writer::to_java_properties_string(
                        transformed_config.iter(),
                    )?;

                    cm_conf_data.insert(file_name.to_string(), node_properties);
                }
                PropertyNameKind::File(file_name) if file_name == HIVE_PROPERTIES => {
                    if let Some(hive_info) = &self.hive_information {
                        transformed_config
                            .insert("connector.name".to_string(), Some("hive".to_string()));
                        transformed_config.insert(
                            "hive.metastore.uri".to_string(),
                            Some(hive_info.full_connection_string()),
                        );

                        let config_properties = product_config::writer::to_java_properties_string(
                            transformed_config.iter(),
                        )?;

                        cm_hive_data.insert(HIVE_PROPERTIES.to_string(), config_properties);
                    }
                }
                PropertyNameKind::File(file_name) if file_name == LOG_PROPERTIES => {
                    let log_properties = product_config::writer::to_java_properties_string(
                        transformed_config.iter(),
                    )?;

                    cm_conf_data.insert(file_name.to_string(), log_properties);
                }
                PropertyNameKind::File(file_name)
                    if file_name == PASSWORD_AUTHENTICATOR_PROPERTIES =>
                {
                    if role == &TrinoRole::Coordinator && !transformed_config.is_empty() {
                        let pw_properties = product_config::writer::to_java_properties_string(
                            transformed_config.iter(),
                        )?;
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
                    // if metrics port is set we need to adapt the
                    if let Some(metrics_port) = config.get(METRICS_PORT_PROPERTY) {
                        jvm_config.push_str(&format!("\n-javaagent:/stackable/jmx/jmx_prometheus_javaagent-0.16.1.jar={}:/stackable/jmx/config.yaml", metrics_port));
                    }
                }
                PropertyNameKind::File(file_name) if file_name == CERTIFICATE_PEM => {
                    if role == &TrinoRole::Coordinator && !config.is_empty() {
                        if let Some(cert_file_content) = config.get(CERT_FILE_CONTENT_MAP_KEY) {
                            cm_conf_data
                                .insert(file_name.to_string(), cert_file_content.to_string());
                        }
                    }
                }
                _ => {}
            }
        }

        cm_conf_data.insert(JVM_CONFIG.to_string(), jvm_config.to_string());

        // check for opa
        if let Some(opa_reference) = &self.context.resource.spec.opa {
            let package = match self.context.resource.spec.authorization.as_ref() {
                Some(auth) => auth.package.clone(),
                None => {
                    warn!("No package specified in 'authorization'. Defaulting to 'trino'.");
                    "trino".to_string()
                }
            };

            let opa_api = OpaApi::Data {
                package_path: package.to_string(),
                rule: "".to_string(),
            };

            let connection_info = util::get_opa_connection_info(
                &self.context.client,
                opa_reference,
                &opa_api,
                &OpaApiProtocol::Http,
                Some(node_name.to_string()),
            )
            .await?;

            debug!(
                "Found valid OPA server [{}]",
                connection_info.connection_string
            );

            let mut opa_config = BTreeMap::new();

            opa_config.insert(
                "access-control.name".to_string(),
                Some("tech.stackable.trino.opa.OpaAuthorizer".to_string()),
            );
            opa_config.insert(
                "opa.policy.uri".to_string(),
                Some(connection_info.connection_string),
            );

            let config_properties =
                product_config::writer::to_java_properties_string(opa_config.iter())?;

            cm_conf_data.insert("access-control.properties".to_string(), config_properties);
        }

        // trino config map
        let mut cm_labels = get_recommended_labels(
            &self.context.resource,
            pod_id.app(),
            &self.context.resource.spec.version.to_string(),
            pod_id.role(),
            pod_id.group(),
        );

        cm_labels.insert(
            configmap::CONFIGMAP_TYPE_LABEL.to_string(),
            CONFIG_MAP_TYPE_CONF.to_string(),
        );

        let cm_conf_name = name_utils::build_resource_name(
            pod_id.app(),
            &self.context.name(),
            pod_id.role(),
            Some(pod_id.group()),
            None,
            Some(CONFIG_MAP_TYPE_CONF),
        )?;

        let cm_config = configmap::build_config_map(
            &self.context.resource,
            &cm_conf_name,
            &self.context.namespace(),
            cm_labels.clone(),
            cm_conf_data,
        )?;

        // hive configmap
        let mut hive_labels = get_recommended_labels(
            &self.context.resource,
            pod_id.app(),
            &self.context.resource.spec.version.to_string(),
            pod_id.role(),
            pod_id.group(),
        );

        hive_labels.insert(
            configmap::CONFIGMAP_TYPE_LABEL.to_string(),
            CONFIG_MAP_TYPE_HIVE.to_string(),
        );

        let cm_hive_name = name_utils::build_resource_name(
            pod_id.app(),
            &self.context.name(),
            pod_id.role(),
            Some(pod_id.group()),
            None,
            Some(CONFIG_MAP_TYPE_HIVE),
        )?;

        let cm_hive = configmap::build_config_map(
            &self.context.resource,
            &cm_hive_name,
            &self.context.namespace(),
            hive_labels,
            cm_hive_data,
        )?;

        config_maps.insert(
            CONFIG_MAP_TYPE_CONF,
            configmap::create_config_map(&self.context.client, cm_config).await?,
        );

        config_maps.insert(
            CONFIG_MAP_TYPE_HIVE,
            configmap::create_config_map(&self.context.client, cm_hive).await?,
        );

        trace!("config_maps to be returned: {:?}", config_maps);
        Ok(config_maps)
    }

    /// Creates the pod required for the Trino instance.
    ///
    /// # Arguments
    ///
    /// - `role` - Trino role.
    /// - `group` - The role group.
    /// - `node_name` - The node name for this pod.
    /// - `config_maps` - The config maps and respective types required for this pod.
    /// - `validated_config` - The validated product config.
    ///
    async fn create_pod(
        &self,
        pod_id: &PodIdentity,
        role: &TrinoRole,
        node_name: &str,
        config_maps: &HashMap<&'static str, ConfigMap>,
        validated_config: &HashMap<PropertyNameKind, BTreeMap<String, String>>,
    ) -> Result<Pod, error::Error> {
        let metrics_port = validated_config
            .get(&PropertyNameKind::File(JVM_CONFIG.to_string()))
            .and_then(|jvm_config| jvm_config.get(METRICS_PORT_PROPERTY));

        let http_port = validated_config
            .get(&PropertyNameKind::File(CONFIG_PROPERTIES.to_string()))
            .and_then(|jvm_config| jvm_config.get(HTTP_SERVER_HTTP_PORT));

        let https_port = validated_config
            .get(&PropertyNameKind::File(CONFIG_PROPERTIES.to_string()))
            .and_then(|jvm_config| jvm_config.get(HTTP_SERVER_HTTPS_PORT));

        let version = &self.context.resource.spec.version;

        let pod_name = name_utils::build_resource_name(
            pod_id.app(),
            &self.context.name(),
            pod_id.role(),
            Some(pod_id.group()),
            Some(node_name),
            None,
        )?;

        let mut recommended_labels = get_recommended_labels(
            &self.context.resource,
            pod_id.app(),
            &version.to_string(),
            pod_id.role(),
            pod_id.group(),
        );
        recommended_labels.insert(ID_LABEL.to_string(), pod_id.id().to_string());

        let mut cb = ContainerBuilder::new(APP_NAME);
        cb.image(format!(
            "docker.stackable.tech/stackable/trino:{}-stackable{}",
            version.to_trino(),
            DEFAULT_IMAGE_VERSION
        ));
        cb.command(role.get_command());

        let mut pod_builder = PodBuilder::new();

        if let Some(config_map_data) = config_maps.get(CONFIG_MAP_TYPE_CONF) {
            if let Some(name) = config_map_data.metadata.name.as_ref() {
                cb.add_volume_mount("config", CONFIG_DIR_NAME);
                pod_builder.add_volume(VolumeBuilder::new("config").with_config_map(name).build());
            } else {
                return Err(error::Error::MissingConfigMapNameError {
                    cm_type: CONFIG_MAP_TYPE_CONF,
                });
            }
        } else {
            return Err(error::Error::MissingConfigMapError {
                cm_type: CONFIG_MAP_TYPE_CONF,
                pod_name,
            });
        }

        // add second volume for hive catalog
        if let Some(config_map_data) = config_maps.get(CONFIG_MAP_TYPE_HIVE) {
            if let Some(name) = config_map_data.metadata.name.as_ref() {
                cb.add_volume_mount("catalog", format!("{}/catalog", CONFIG_DIR_NAME));
                pod_builder.add_volume(VolumeBuilder::new("catalog").with_config_map(name).build());
            } else {
                return Err(error::Error::MissingConfigMapNameError {
                    cm_type: CONFIG_MAP_TYPE_HIVE,
                });
            }
        } else {
            return Err(error::Error::MissingConfigMapError {
                cm_type: CONFIG_MAP_TYPE_HIVE,
                pod_name,
            });
        }

        let mut annotations = BTreeMap::new();
        // only add metrics container port and annotation if required
        if let Some(metrics_port) = metrics_port {
            annotations.insert(SHOULD_BE_SCRAPED.to_string(), "true".to_string());
            cb.add_container_port(METRICS_PORT, metrics_port.parse()?);
        }

        if let Some(http_port) = http_port {
            cb.add_container_port(HTTP_PORT, http_port.parse()?);
        }

        if let Some(https_port) = https_port {
            cb.add_container_port(HTTPS_PORT, https_port.parse()?);
        }

        let pod = pod_builder
            .metadata(
                ObjectMetaBuilder::new()
                    .generate_name(pod_name)
                    .namespace(&self.context.client.default_namespace)
                    .with_labels(recommended_labels)
                    .with_annotations(annotations)
                    .ownerreference_from_resource(&self.context.resource, Some(true), Some(true))?
                    .build()?,
            )
            .add_container(cb.build())
            .node_name(node_name)
            .host_network(true)
            .build()?;

        trace!("create_pod: {:?}", pod_id);
        Ok(self.context.client.create(&pod).await?)
    }

    async fn delete_all_pods(&self) -> OperatorResult<ReconcileFunctionAction> {
        for pod in &self.existing_pods {
            self.context.client.delete(pod).await?;
        }
        Ok(ReconcileFunctionAction::Done)
    }

    pub async fn process_command(&mut self) -> TrinoReconcileResult {
        match self.context.retrieve_current_command().await? {
            // if there is no new command and the execution status is stopped we stop the
            // reconcile loop here.
            None => match self.context.resource.cluster_execution_status() {
                Some(execution_status) if execution_status == ClusterExecutionStatus::Stopped => {
                    Ok(ReconcileFunctionAction::Done)
                }
                _ => Ok(ReconcileFunctionAction::Continue),
            },
            Some(command_ref) => match command_ref.kind.as_str() {
                "Restart" => {
                    info!("Restarting cluster [{:?}]", command_ref);
                    let mut restart_command: Restart =
                        materialize_command(&self.context.client, &command_ref).await?;
                    Ok(self.context.default_restart(&mut restart_command).await?)
                }
                "Start" => {
                    info!("Starting cluster [{:?}]", command_ref);
                    let mut start_command: Start =
                        materialize_command(&self.context.client, &command_ref).await?;
                    Ok(self.context.default_start(&mut start_command).await?)
                }
                "Stop" => {
                    info!("Stopping cluster [{:?}]", command_ref);
                    let mut stop_command: Stop =
                        materialize_command(&self.context.client, &command_ref).await?;

                    Ok(self.context.default_stop(&mut stop_command).await?)
                }
                _ => {
                    error!("Got unknown type of command: [{:?}]", command_ref);
                    Ok(ReconcileFunctionAction::Done)
                }
            },
        }
    }
}

impl ReconciliationState for TrinoState {
    type Error = error::Error;

    fn reconcile(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<ReconcileFunctionAction, Self::Error>> + Send + '_>>
    {
        info!("========================= Starting reconciliation =========================");

        Box::pin(async move {
            self.init_status()
                .await?
                .then(self.context.handle_deletion(
                    Box::pin(self.delete_all_pods()),
                    FINALIZER_NAME,
                    true,
                ))
                .await?
                .then(self.context.delete_illegal_pods(
                    self.existing_pods.as_slice(),
                    &self.get_required_labels(),
                    ContinuationStrategy::OneRequeue,
                ))
                .await?
                .then(
                    self.context
                        .wait_for_terminating_pods(self.existing_pods.as_slice()),
                )
                .await?
                .then(
                    self.context
                        .wait_for_running_and_ready_pods(&self.existing_pods),
                )
                .await?
                .then(self.create_rego_rules())
                .await?
                .then(self.process_command())
                .await?
                .then(self.context.delete_excess_pods(
                    list_eligible_nodes_for_role_and_group(&self.eligible_nodes).as_slice(),
                    &self.existing_pods,
                    ContinuationStrategy::OneRequeue,
                ))
                .await?
                .then(self.get_hive_connection_information())
                .await?
                .then(self.get_trino_discovery())
                .await?
                .then(self.create_missing_pods())
                .await
        })
    }
}

struct TrinoStrategy {
    config: Arc<ProductConfigManager>,
}

impl TrinoStrategy {
    pub fn new(config: ProductConfigManager) -> TrinoStrategy {
        TrinoStrategy {
            config: Arc::new(config),
        }
    }
}

#[async_trait]
impl ControllerStrategy for TrinoStrategy {
    type Item = TrinoCluster;
    type State = TrinoState;
    type Error = Error;

    /// Init the Trino state. Store all available pods owned by this cluster for later processing.
    /// Retrieve nodes that fit selectors and store them for later processing:
    /// TrinoRole (we only have 'server') -> role group -> list of nodes.
    async fn init_reconcile_state(
        &self,
        context: ReconciliationContext<Self::Item>,
    ) -> Result<Self::State, Self::Error> {
        let existing_pods = context
            .list_owned(build_common_labels_for_all_managed_resources(
                APP_NAME,
                &context.resource.name(),
            ))
            .await?;
        trace!(
            "{}: Found [{}] pods",
            context.log_name(),
            existing_pods.len()
        );

        let trino_spec: TrinoClusterSpec = context.resource.spec.clone();

        let mut eligible_nodes = HashMap::new();

        eligible_nodes.insert(
            TrinoRole::Worker.to_string(),
            role_utils::find_nodes_that_fit_selectors(&context.client, None, &trino_spec.workers)
                .await?,
        );

        eligible_nodes.insert(
            TrinoRole::Coordinator.to_string(),
            role_utils::find_nodes_that_fit_selectors(
                &context.client,
                None,
                &trino_spec.coordinators,
            )
            .await?,
        );

        trace!("Eligible Nodes: {:?}", eligible_nodes);

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
                context.resource.spec.coordinators.clone().into(),
            ),
        );

        roles.insert(
            TrinoRole::Worker.to_string(),
            (config_files, context.resource.spec.workers.clone().into()),
        );

        let role_config = transform_all_roles_to_config(&context.resource, roles);
        let validated_role_config = validate_all_roles_and_groups_config(
            &context.resource.spec.version.to_string(),
            &role_config,
            &self.config,
            false,
            false,
        )?;

        Ok(TrinoState {
            context,
            existing_pods,
            eligible_nodes,
            validated_role_config,
            trino_discovery: None,
            hive_information: None,
        })
    }
}

/// This creates an instance of a [`Controller`] which waits for incoming events and reconciles them.
///
/// This is an async method and the returned future needs to be consumed to make progress.
pub async fn create_controller(client: Client, product_config_path: &str) -> OperatorResult<()> {
    let api: Api<TrinoCluster> = client.get_all_api();
    let pods_api: Api<Pod> = client.get_all_api();
    let config_maps_api: Api<ConfigMap> = client.get_all_api();
    let cmd_restart_api: Api<Restart> = client.get_all_api();
    let cmd_start_api: Api<Start> = client.get_all_api();
    let cmd_stop_api: Api<Stop> = client.get_all_api();

    let controller = Controller::new(api)
        .owns(pods_api, ListParams::default())
        .owns(config_maps_api, ListParams::default())
        .owns(cmd_restart_api, ListParams::default())
        .owns(cmd_start_api, ListParams::default())
        .owns(cmd_stop_api, ListParams::default());

    let product_config = ProductConfigManager::from_yaml_file(product_config_path).unwrap();

    let strategy = TrinoStrategy::new(product_config);

    controller
        .run(client, strategy, Duration::from_secs(10))
        .await;

    Ok(())
}
