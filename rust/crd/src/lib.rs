pub mod authentication;
pub mod discovery;

use crate::{authentication::Authentication, discovery::TrinoPodRef};

use serde::{Deserialize, Serialize};
use snafu::{OptionExt, Snafu};
use stackable_operator::commons::opa::OpaConfig;
use stackable_operator::commons::s3::S3ConnectionDef;
use stackable_operator::{
    kube::{runtime::reflector::ObjectRef, CustomResource, ResourceExt},
    product_config_utils::{ConfigError, Configuration},
    role_utils::{Role, RoleGroupRef},
    schemars::{self, JsonSchema},
};
use std::{collections::BTreeMap, str::FromStr};
use strum::{Display, EnumIter, IntoEnumIterator};

pub const APP_NAME: &str = "trino";
pub const FIELD_MANAGER_SCOPE: &str = "trinocluster";
// ports
pub const HTTP_PORT: u16 = 8080;
pub const HTTPS_PORT: u16 = 8443;
pub const METRICS_PORT: u16 = 8081;
// port names
pub const HTTP_PORT_NAME: &str = "http";
pub const HTTPS_PORT_NAME: &str = "https";
pub const METRICS_PORT_NAME: &str = "metrics";
// file names
pub const CONFIG_PROPERTIES: &str = "config.properties";
pub const JVM_CONFIG: &str = "jvm.config";
pub const NODE_PROPERTIES: &str = "node.properties";
pub const LOG_PROPERTIES: &str = "log.properties";
pub const PASSWORD_AUTHENTICATOR_PROPERTIES: &str = "password-authenticator.properties";
pub const PASSWORD_DB: &str = "password.db";
pub const HIVE_PROPERTIES: &str = "hive.properties";
pub const ACCESS_CONTROL_PROPERTIES: &str = "access-control.properties";
// node.properties
pub const NODE_ENVIRONMENT: &str = "node.environment";
pub const NODE_ID: &str = "node.id";
pub const NODE_DATA_DIR: &str = "node.data-dir";
// config.properties
pub const COORDINATOR: &str = "coordinator";
pub const HTTP_SERVER_HTTP_PORT: &str = "http-server.http.port";
pub const HTTP_SERVER_HTTPS_PORT: &str = "http-server.https.port";
pub const HTTP_SERVER_HTTPS_ENABLED: &str = "http-server.https.enabled";
pub const HTTP_SERVER_HTTPS_KEYSTORE_KEY: &str = "http-server.https.keystore.key";
pub const HTTP_SERVER_KEYSTORE_PATH: &str = "http-server.https.keystore.path";
pub const HTTP_SERVER_AUTHENTICATION_TYPE: &str = "http-server.authentication.type";
pub const HTTP_SERVER_AUTHENTICATION_TYPE_PASSWORD: &str = "PASSWORD";
pub const QUERY_MAX_MEMORY: &str = "query.max-memory";
pub const QUERY_MAX_MEMORY_PER_NODE: &str = "query.max-memory-per-node";
pub const DISCOVERY_URI: &str = "discovery.uri";
// password-authenticator.properties
pub const PASSWORD_AUTHENTICATOR_NAME: &str = "password-authenticator.name";
pub const PASSWORD_AUTHENTICATOR_NAME_FILE: &str = "file";
pub const FILE_PASSWORD_FILE: &str = "file.password-file";
// file content keys
pub const PW_FILE_CONTENT_MAP_KEY: &str = "pwFileContent";
pub const CERT_FILE_CONTENT_MAP_KEY: &str = "serverCertificate";
// hive.properties
pub const S3_ENDPOINT: &str = "hive.s3.endpoint";
pub const S3_ACCESS_KEY: &str = "hive.s3.aws-access-key";
pub const S3_SECRET_KEY: &str = "hive.s3.aws-secret-key";
pub const S3_SSL_ENABLED: &str = "hive.s3.ssl.enabled";
pub const S3_PATH_STYLE_ACCESS: &str = "hive.s3.path-style-access";
pub const DEFAULT_PATH_STYLE_ACCESS: bool = false;
// log.properties
pub const IO_TRINO: &str = "io.trino";
// jvm.config
pub const METRICS_PORT_PROPERTY: &str = "metricsPort";
// directories
pub const CONFIG_DIR_NAME: &str = "/stackable/conf";
pub const RW_CONFIG_DIR_NAME: &str = "/stackable/rwconf";
pub const DATA_DIR_NAME: &str = "/stackable/data";
pub const KEYSTORE_DIR_NAME: &str = "/stackable/keystore";
pub const USER_PASSWORD_DATA_DIR_NAME: &str = "/stackable/users";

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("object has no namespace associated"))]
    NoNamespace,
    #[snafu(display("Unknown Trino role found {role}. Should be one of {roles:?}"))]
    UnknownTrinoRole { role: String, roles: Vec<String> },
}

#[derive(Clone, CustomResource, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[kube(
    group = "trino.stackable.tech",
    version = "v1alpha1",
    kind = "TrinoCluster",
    plural = "trinoclusters",
    shortname = "trino",
    namespaced,
    crates(
        kube_core = "stackable_operator::kube::core",
        k8s_openapi = "stackable_operator::k8s_openapi",
        schemars = "stackable_operator::schemars"
    )
)]
#[kube(status = "TrinoClusterStatus")]
#[serde(rename_all = "camelCase")]
pub struct TrinoClusterSpec {
    /// Emergency stop button, if `true` then all pods are stopped without affecting configuration (as setting `replicas` to `0` would)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stopped: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hive_config_map_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub opa: Option<OpaConfig>,
    /// A reference to a secret containing username/password for defined users
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentication: Option<Authentication>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub s3: Option<S3ConnectionDef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coordinators: Option<Role<TrinoConfig>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workers: Option<Role<TrinoConfig>>,
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
    /// Returns the container start command for a Trino node.
    pub fn get_command(&self) -> Vec<String> {
        vec![
            "bin/launcher".to_string(),
            "run".to_string(),
            format!("--etc-dir={}", CONFIG_DIR_NAME),
        ]
    }

    pub fn get_spec<'a>(&self, trino: &'a TrinoCluster) -> Option<&'a Role<TrinoConfig>> {
        match self {
            TrinoRole::Coordinator => trino.spec.coordinators.as_ref(),
            TrinoRole::Worker => trino.spec.workers.as_ref(),
        }
    }

    /// Metadata about a rolegroup
    pub fn rolegroup_ref(
        &self,
        trino: &TrinoCluster,
        group_name: impl Into<String>,
    ) -> RoleGroupRef<TrinoCluster> {
        RoleGroupRef {
            cluster: ObjectRef::from_obj(trino),
            role: self.to_string(),
            role_group: group_name.into(),
        }
    }

    pub fn roles() -> Vec<String> {
        let mut roles = vec![];
        for role in Self::iter() {
            roles.push(role.to_string())
        }
        roles
    }
}

impl FromStr for TrinoRole {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == Self::Coordinator.to_string() {
            Ok(Self::Coordinator)
        } else if s == Self::Worker.to_string() {
            Ok(Self::Worker)
        } else {
            Err(Error::UnknownTrinoRole {
                role: s.to_string(),
                roles: TrinoRole::roles(),
            })
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrinoClusterStatus {}

#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrinoConfig {
    // config.properties
    pub query_max_memory: Option<String>,
    pub query_max_memory_per_node: Option<String>,
    // log.properties
    pub log_level: Option<String>,
}

impl Configuration for TrinoConfig {
    type Configurable = TrinoCluster;

    fn compute_env(
        &self,
        _resource: &Self::Configurable,
        _role_name: &str,
    ) -> Result<BTreeMap<String, Option<String>>, ConfigError> {
        Ok(BTreeMap::new())
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
        role_name: &str,
        file: &str,
    ) -> Result<BTreeMap<String, Option<String>>, ConfigError> {
        let mut result = BTreeMap::new();

        match file {
            NODE_PROPERTIES => {
                // The resource name is alphanumeric and may have "-" characters
                // The Trino node environment is bound to alphanumeric lowercase and "_" characters
                // and must start with alphanumeric (which is the case for resource names as well?)
                // see https://trino.io/docs/current/installation/deployment.html
                let node_env = resource.name().to_ascii_lowercase().replace('-', "_");
                result.insert(NODE_ENVIRONMENT.to_string(), Some(node_env));
            }
            CONFIG_PROPERTIES => {
                if role_name == TrinoRole::Coordinator.to_string() {
                    result.insert(COORDINATOR.to_string(), Some("true".to_string()));
                } else {
                    result.insert(COORDINATOR.to_string(), Some("false".to_string()));
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

                if resource.spec.authentication.is_some() {
                    result.insert(
                        HTTP_SERVER_HTTPS_ENABLED.to_string(),
                        Some(true.to_string()),
                    );
                    result.insert(
                        HTTP_SERVER_HTTPS_PORT.to_string(),
                        Some(HTTPS_PORT.to_string()),
                    );
                    result.insert(
                        HTTP_SERVER_KEYSTORE_PATH.to_string(),
                        Some(format!("{}/{}", KEYSTORE_DIR_NAME, "keystore.p12")),
                    );

                    result.insert(
                        HTTP_SERVER_HTTPS_KEYSTORE_KEY.to_string(),
                        Some("secret".to_string()),
                    );

                    // password ui login
                    if role_name == TrinoRole::Coordinator.to_string() {
                        result.insert(
                            HTTP_SERVER_AUTHENTICATION_TYPE.to_string(),
                            Some(HTTP_SERVER_AUTHENTICATION_TYPE_PASSWORD.to_string()),
                        );
                    }
                }
            }
            PASSWORD_AUTHENTICATOR_PROPERTIES => {
                if resource.spec.authentication.is_some() {
                    result.insert(
                        PASSWORD_AUTHENTICATOR_NAME.to_string(),
                        Some(PASSWORD_AUTHENTICATOR_NAME_FILE.to_string()),
                    );
                    result.insert(
                        FILE_PASSWORD_FILE.to_string(),
                        Some(format!("{}/{}", USER_PASSWORD_DATA_DIR_NAME, PASSWORD_DB)),
                    );
                }
            }
            LOG_PROPERTIES => {
                if let Some(log_level) = &self.log_level {
                    result.insert(IO_TRINO.to_string(), Some(log_level.to_string()));
                }
            }
            _ => {}
        }

        Ok(result)
    }
}

impl TrinoCluster {
    /// The name of the role-level load-balanced Kubernetes `Service` for the worker nodes
    pub fn worker_role_service_name(&self) -> Option<String> {
        self.metadata
            .name
            .as_ref()
            .map(|name| format!("{}-worker", name))
    }

    /// The name of the role-level load-balanced Kubernetes `Service` for the coordinator nodes
    pub fn coordinator_role_service_name(&self) -> Option<String> {
        self.metadata
            .name
            .as_ref()
            .map(|name| format!("{}-coordinator", name))
    }

    /// The fully-qualified domain name of the role-level load-balanced Kubernetes `Service`
    pub fn coordinator_role_service_fqdn(&self) -> Option<String> {
        Some(format!(
            "{}.{}.svc.cluster.local",
            self.coordinator_role_service_name()?,
            self.metadata.namespace.as_ref()?
        ))
    }

    /// The fully-qualified domain name of the role-level load-balanced Kubernetes `Service`
    pub fn worker_role_service_fqdn(&self) -> Option<String> {
        Some(format!(
            "{}.{}.svc.cluster.local",
            self.worker_role_service_name()?,
            self.metadata.namespace.as_ref()?
        ))
    }

    /// List all coordinator pods expected to form the cluster
    ///
    /// We try to predict the pods here rather than looking at the current cluster state in order to
    /// avoid instance churn.
    pub fn coordinator_pods(&self) -> Result<impl Iterator<Item = TrinoPodRef> + '_, Error> {
        let ns = self.metadata.namespace.clone().context(NoNamespaceSnafu)?;
        Ok(self
            .spec
            .coordinators
            .iter()
            .flat_map(|role| &role.role_groups)
            // Order rolegroups consistently, to avoid spurious downstream rewrites
            .collect::<BTreeMap<_, _>>()
            .into_iter()
            .flat_map(move |(rolegroup_name, rolegroup)| {
                let rolegroup_ref = TrinoRole::Coordinator.rolegroup_ref(self, rolegroup_name);
                let ns = ns.clone();
                (0..rolegroup.replicas.unwrap_or(0)).map(move |i| TrinoPodRef {
                    namespace: ns.clone(),
                    role_group_service_name: rolegroup_ref.object_name(),
                    pod_name: format!("{}-{}", rolegroup_ref.object_name(), i),
                })
            }))
    }
}
