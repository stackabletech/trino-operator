pub mod commands;
pub mod error;

use crate::commands::{Restart, Start, Stop};

use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use k8s_openapi::schemars::_serde_json::Value;
use kube::api::ApiResource;
use kube::CustomResource;
use kube::CustomResourceExt;
use schemars::JsonSchema;
use semver::Version;
use serde::{Deserialize, Serialize};
use serde_json::json;
use stackable_operator::command::{CommandRef, HasCommands, HasRoleRestartOrder};
use stackable_operator::controller::HasOwned;
use stackable_operator::crd::HasApplication;
use stackable_operator::identity::PodToNodeMapping;
use stackable_operator::product_config_utils::{ConfigError, Configuration};
use stackable_operator::role_utils::Role;
use stackable_operator::status::{
    ClusterExecutionStatus, Conditions, HasClusterExecutionStatus, HasCurrentCommand, Status,
    Versioned,
};
use stackable_operator::versioning::{ProductVersion, Versioning, VersioningState};
use std::cmp::Ordering;
use std::collections::BTreeMap;
use strum_macros::Display;
use strum_macros::EnumIter;

pub const APP_NAME: &str = "trino";
pub const MANAGED_BY: &str = "trino-operator";

pub const NODE_ENVIRONMENT: &str = "node.environment";
pub const NODE_ID: &str = "node.id";
pub const NODE_DATA_DIR: &str = "node.data-dir";
pub const COORDINATOR: &str = "coordinator";
pub const HTTP_SERVER_PORT: &str = "http-server.http.port";
pub const QUERY_MAX_MEMORY: &str = "query.max-memory";
pub const QUERY_MAX_MEMORY_PER_NODE: &str = "query.max-memory-per-node";
pub const QUERY_MAX_TOTAL_MEMORY_PER_NODE: &str = "query.max-total-memory-per-node";
pub const DISCOVERY_URI: &str = "discovery.uri";
pub const IO_TRINO: &str = "io.trino";

pub const CONFIG_MAP_TYPE_DATA: &str = "data";
pub const CONFIG_MAP_TYPE_ID: &str = "id";

pub const CONFIG_DIR_NAME: &str = "conf";

#[derive(Clone, CustomResource, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[kube(
    group = "trino.stackable.tech",
    version = "v1alpha1",
    kind = "TrinoCluster",
    plural = "trinoclusters",
    shortname = "trino",
    namespaced
)]
#[kube(status = "TrinoClusterStatus")]
#[serde(rename_all = "camelCase")]
pub struct TrinoClusterSpec {
    pub version: TrinoVersion,
    pub coordinators: Role<TrinoConfig>,
    pub workers: Role<TrinoConfig>,
    pub node_environment: String,
}

#[derive(
    Clone, Debug, Deserialize, Display, EnumIter, Eq, Hash, JsonSchema, PartialEq, Serialize,
)]
pub enum TrinoRole {
    #[strum(serialize = "coordinator")]
    Coordinator,
    #[strum(serialize = "worker")]
    Worker,
}

impl TrinoRole {
    /// Returns the container start command for a HDFS node
    /// Right now works only for images using hadoop2.7
    /// # Arguments
    ///
    /// * `version` - Current specified cluster version
    pub fn get_command(&self, version: &TrinoVersion) -> Vec<String> {
        let parsed_version = Version::parse(version.to_string().as_ref()).unwrap();

        vec![
            format!("trino-server-{}/bin/launcher", parsed_version.patch),
            // run or start?
            "start".to_string(),
            "--etc-dir=".to_string(),
            format!("{{{{configroot}}}}/{}", CONFIG_DIR_NAME),
        ]
    }
}

impl Status<TrinoClusterStatus> for TrinoCluster {
    fn status(&self) -> &Option<TrinoClusterStatus> {
        &self.status
    }
    fn status_mut(&mut self) -> &mut Option<TrinoClusterStatus> {
        &mut self.status
    }
}

impl HasRoleRestartOrder for TrinoCluster {
    fn get_role_restart_order() -> Vec<String> {
        vec![
            TrinoRole::Worker.to_string(),
            TrinoRole::Coordinator.to_string(),
        ]
    }
}

impl HasCommands for TrinoCluster {
    fn get_command_types() -> Vec<ApiResource> {
        vec![
            Start::api_resource(),
            Stop::api_resource(),
            Restart::api_resource(),
        ]
    }
}

impl HasOwned for TrinoCluster {
    fn owned_objects() -> Vec<&'static str> {
        vec![Restart::crd_name(), Start::crd_name(), Stop::crd_name()]
    }
}

impl HasApplication for TrinoCluster {
    fn get_application_name() -> &'static str {
        APP_NAME
    }
}

impl HasClusterExecutionStatus for TrinoCluster {
    fn cluster_execution_status(&self) -> Option<ClusterExecutionStatus> {
        self.status
            .as_ref()
            .and_then(|status| status.cluster_execution_status.clone())
    }

    fn cluster_execution_status_patch(&self, execution_status: &ClusterExecutionStatus) -> Value {
        json!({ "clusterExecutionStatus": execution_status })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrinoConfig {
    pub node_id: Option<String>,
    pub node_data_dir: Option<String>,
    pub coordinator: Option<bool>,
    pub http_server_http_port: Option<u16>,
    pub query_max_memory: Option<String>,
    pub query_max_memory_per_node: Option<String>,
    pub query_max_total_memory_per_node: Option<String>,
    // TODO: read from coordiantor(s)
    pub discovery_uri: Option<String>,
    pub io_trino: Option<String>,
}

impl Configuration for TrinoConfig {
    type Configurable = TrinoCluster;

    fn compute_env(
        &self,
        _resource: &Self::Configurable,
        _role_name: &str,
    ) -> Result<BTreeMap<String, Option<String>>, ConfigError> {
        let mut result = BTreeMap::new();

        // TODO: Readd if we want jmx metrics gathered
        //if let Some(metrics_port) = self.metrics_port {
        //    result.insert(METRICS_PORT.to_string(), Some(metrics_port.to_string()));
        // }
        Ok(result)
    }

    fn compute_cli(
        &self,
        _resource: &Self::Configurable,
        _role_name: &str,
    ) -> Result<BTreeMap<String, Option<String>>, ConfigError> {
        Ok(BTreeMap::new())
    }

    fn compute_files(
        &self,
        resource: &Self::Configurable,
        _role_name: &str,
        _file: &str,
    ) -> Result<BTreeMap<String, Option<String>>, ConfigError> {
        let mut result = BTreeMap::new();

        result.insert(
            NODE_ENVIRONMENT.to_string(),
            Some(resource.spec.node_environment.clone()),
        );

        if let Some(node_id) = &self.node_id {
            result.insert(NODE_ID.to_string(), Some(node_id.to_string()));
        }

        if let Some(node_data_dir) = &self.node_data_dir {
            result.insert(NODE_DATA_DIR.to_string(), Some(node_data_dir.to_string()));
        }

        if let Some(coordinator) = &self.coordinator {
            result.insert(COORDINATOR.to_string(), Some(coordinator.to_string()));
        }

        if let Some(http_server_http_port) = &self.http_server_http_port {
            result.insert(
                HTTP_SERVER_PORT.to_string(),
                Some(http_server_http_port.to_string()),
            );
        }

        if let Some(query_max_memory) = &self.query_max_memory {
            result.insert(
                QUERY_MAX_MEMORY.to_string(),
                Some(query_max_memory.to_string()),
            );
        }

        if let Some(query_max_memory_per_node) = &self.query_max_memory_per_node {
            result.insert(
                QUERY_MAX_MEMORY_PER_NODE.to_string(),
                Some(query_max_memory_per_node.to_string()),
            );
        }

        if let Some(query_max_total_memory_per_node) = &self.query_max_total_memory_per_node {
            result.insert(
                QUERY_MAX_TOTAL_MEMORY_PER_NODE.to_string(),
                Some(query_max_total_memory_per_node.to_string()),
            );
        }

        if let Some(io_trino) = &self.io_trino {
            result.insert(IO_TRINO.to_string(), Some(io_trino.to_string()));
        }

        Ok(result)
    }
}

#[allow(non_camel_case_types)]
#[derive(
    Clone,
    Debug,
    Deserialize,
    Eq,
    JsonSchema,
    PartialEq,
    Serialize,
    strum_macros::Display,
    strum_macros::EnumString,
)]
pub enum TrinoVersion {
    #[serde(rename = "0.0.360")]
    #[strum(serialize = "0.0.360")]
    v360,

    #[serde(rename = "0.0.361")]
    #[strum(serialize = "0.0.361")]
    v361,

    #[serde(rename = "0.0.362")]
    #[strum(serialize = "0.0.362")]
    v362,
}

impl TrinoVersion {
    pub fn package_name(&self) -> String {
        format!("trino-server:{}", self.to_string())
    }
}

impl Versioning for TrinoVersion {
    fn versioning_state(&self, other: &Self) -> VersioningState {
        let from_version = match Version::parse(&self.to_string()) {
            Ok(v) => v,
            Err(e) => {
                return VersioningState::Invalid(format!(
                    "Could not parse [{}] to SemVer: {}",
                    self.to_string(),
                    e.to_string()
                ))
            }
        };

        let to_version = match Version::parse(&other.to_string()) {
            Ok(v) => v,
            Err(e) => {
                return VersioningState::Invalid(format!(
                    "Could not parse [{}] to SemVer: {}",
                    other.to_string(),
                    e.to_string()
                ))
            }
        };

        match to_version.cmp(&from_version) {
            Ordering::Greater => VersioningState::ValidUpgrade,
            Ordering::Less => VersioningState::ValidDowngrade,
            Ordering::Equal => VersioningState::NoOp,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrinoClusterStatus {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<ProductVersion<TrinoVersion>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub history: Option<PodToNodeMapping>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_command: Option<CommandRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cluster_execution_status: Option<ClusterExecutionStatus>,
}

impl Versioned<TrinoVersion> for TrinoClusterStatus {
    fn version(&self) -> &Option<ProductVersion<TrinoVersion>> {
        &self.version
    }
    fn version_mut(&mut self) -> &mut Option<ProductVersion<TrinoVersion>> {
        &mut self.version
    }
}

impl Conditions for TrinoClusterStatus {
    fn conditions(&self) -> &[Condition] {
        self.conditions.as_slice()
    }
    fn conditions_mut(&mut self) -> &mut Vec<Condition> {
        &mut self.conditions
    }
}

impl HasCurrentCommand for TrinoClusterStatus {
    fn current_command(&self) -> Option<CommandRef> {
        self.current_command.clone()
    }
    fn set_current_command(&mut self, command: CommandRef) {
        self.current_command = Some(command);
    }
    fn clear_current_command(&mut self) {
        self.current_command = None
    }
    fn tracking_location() -> &'static str {
        "/status/currentCommand"
    }
}

#[cfg(test)]
mod tests {
    use crate::TrinoVersion;
    use semver::Version;
    use stackable_operator::versioning::{Versioning, VersioningState};
    use std::str::FromStr;

    #[test]
    fn test_trino_version_versioning() {
        assert_eq!(
            TrinoVersion::v361.versioning_state(&TrinoVersion::v361),
            VersioningState::ValidUpgrade
        );
        assert_eq!(
            TrinoVersion::v361.versioning_state(&TrinoVersion::v361),
            VersioningState::ValidDowngrade
        );
        assert_eq!(
            TrinoVersion::v361.versioning_state(&TrinoVersion::v361),
            VersioningState::NoOp
        );
    }

    #[test]
    #[test]
    fn test_version_conversion() {
        // TODO: Adapt to correct product version
        // TrinoVersion::from_str("3.4.14").unwrap();
    }

    #[test]
    fn test_package_name() {
        // TODO: Adapot to correct package names
        assert_eq!(
            TrinoVersion::v360.package_name(),
            format!("trino-{}", TrinoVersion::v360.to_string())
        );
        assert_eq!(
            TrinoVersion::v360.package_name(),
            format!("trino-server-{}", TrinoVersion::v360.to_string())
        );
    }

    #[test]
    fn test_semver() {
        let test = Version::parse("0.0.360").unwrap();
        println!("{}", test);
    }
}
