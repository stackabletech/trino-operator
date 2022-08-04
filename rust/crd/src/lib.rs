pub mod authentication;
pub mod discovery;

use crate::{authentication::Authentication, discovery::TrinoPodRef};

use serde::{Deserialize, Serialize};
use snafu::{OptionExt, Snafu};
use stackable_operator::{
    commons::{opa::OpaConfig, s3::S3ConnectionDef},
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
// config.properties
pub const COORDINATOR: &str = "coordinator";
pub const DISCOVERY_URI: &str = "discovery.uri";
pub const HTTP_SERVER_HTTP_PORT: &str = "http-server.http.port";
pub const QUERY_MAX_MEMORY: &str = "query.max-memory";
pub const QUERY_MAX_MEMORY_PER_NODE: &str = "query.max-memory-per-node";
// - client tls
pub const HTTP_SERVER_HTTPS_PORT: &str = "http-server.https.port";
pub const HTTP_SERVER_HTTPS_ENABLED: &str = "http-server.https.enabled";
pub const HTTP_SERVER_HTTPS_KEYSTORE_KEY: &str = "http-server.https.keystore.key";
pub const HTTP_SERVER_KEYSTORE_PATH: &str = "http-server.https.keystore.path";
pub const HTTP_SERVER_HTTPS_TRUSTSTORE_KEY: &str = "http-server.https.truststore.key";
pub const HTTP_SERVER_TRUSTSTORE_PATH: &str = "http-server.https.truststore.path";
pub const HTTP_SERVER_AUTHENTICATION_ALLOW_INSECURE_OVER_HTTP: &str =
    "http-server.authentication.allow-insecure-over-http";
// - internal tls
pub const INTERNAL_COMMUNICATION_SHARED_SECRET: &str = "internal-communication.shared-secret";
pub const INTERNAL_COMMUNICATION_HTTPS_KEYSTORE_PATH: &str =
    "internal-communication.https.keystore.path";
pub const INTERNAL_COMMUNICATION_HTTPS_KEYSTORE_KEY: &str =
    "internal-communication.https.keystore.key";
pub const INTERNAL_COMMUNICATION_HTTPS_TRUSTSTORE_PATH: &str =
    "internal-communication.https.truststore.path";
pub const INTERNAL_COMMUNICATION_HTTPS_TRUSTSTORE_KEY: &str =
    "internal-communication.https.truststore.key";
pub const NODE_INTERNAL_ADDRESS_SOURCE: &str = "node.internal-address-source";
pub const NODE_INTERNAL_ADDRESS_SOURCE_FQDN: &str = "FQDN";
// - authentication
pub const HTTP_SERVER_AUTHENTICATION_TYPE: &str = "http-server.authentication.type";
pub const HTTP_SERVER_AUTHENTICATION_TYPE_PASSWORD: &str = "PASSWORD";
// password-authenticator.properties
pub const PASSWORD_AUTHENTICATOR_NAME: &str = "password-authenticator.name";
pub const PASSWORD_AUTHENTICATOR_NAME_FILE: &str = "file";
pub const FILE_PASSWORD_FILE: &str = "file.password-file";
// hive.properties
pub const S3_ENDPOINT: &str = "hive.s3.endpoint";
pub const S3_ACCESS_KEY: &str = "hive.s3.aws-access-key";
pub const S3_SECRET_KEY: &str = "hive.s3.aws-secret-key";
pub const S3_SSL_ENABLED: &str = "hive.s3.ssl.enabled";
pub const S3_PATH_STYLE_ACCESS: &str = "hive.s3.path-style-access";
// log.properties
pub const IO_TRINO: &str = "io.trino";
// jvm.config
pub const METRICS_PORT_PROPERTY: &str = "metricsPort";
// directories
pub const CONFIG_DIR_NAME: &str = "/stackable/config";
pub const RW_CONFIG_DIR_NAME: &str = "/stackable/rwconfig";
pub const DATA_DIR_NAME: &str = "/stackable/data";
pub const USER_PASSWORD_DATA_DIR_NAME: &str = "/stackable/users";
pub const S3_SECRET_DIR_NAME: &str = "/stackable/secrets";
pub const STACKABLE_CLIENT_TLS_DIR: &str = "/stackable/client_tls";
pub const STACKABLE_INTERNAL_TLS_DIR: &str = "/stackable/internal_tls";
pub const SYSTEM_TRUST_STORE: &str = "/etc/pki/java/cacerts";
// store pws
pub const STACKABLE_TLS_STORE_PASSWORD: &str = "changeit";
pub const SYSTEM_TRUST_STORE_PASSWORD: &str = "changeit";
// secret vars
pub const ENV_INTERNAL_SECRET: &str = "INTERNAL_SECRET";
// S3 secrets
pub const ENV_S3_ACCESS_KEY: &str = "S3_ACCESS_KEY";
pub const ENV_S3_SECRET_KEY: &str = "S3_SECRET_KEY";
pub const SECRET_KEY_S3_ACCESS_KEY: &str = "accessKey";
pub const SECRET_KEY_S3_SECRET_KEY: &str = "secretKey";
// TLS
pub const TLS_DEFAULT_SECRET_CLASS: &str = "tls";

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("could not parse product version from image: [{image_version}]. Expected format e.g. [387-stackable0.1.0]"))]
    TrinoProductVersion { image_version: String },
    #[snafu(display("object has no namespace associated"))]
    NoNamespace,
    #[snafu(display("object defines no version"))]
    ObjectHasNoVersion,
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
    /// Emergency stop button, if `true` then all pods are stopped without affecting configuration (as setting `replicas` to `0` would).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stopped: Option<bool>,
    /// The provided trino image version in the form `xxx-stackableY.Y.Y` e.g. `387-stackable0.1.0`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// The discovery ConfigMap name of the Hive cluster (usually the same as the Hive cluster name).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hive_config_map_name: Option<String>,
    /// The discovery ConfigMap name of the OPA cluster (usually the same as the OPA cluster name).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub opa: Option<OpaConfig>,
    /// Global Trino Config for cluster settings like TLS
    #[serde(default)]
    pub config: GlobalTrinoConfig,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication: Option<Authentication>,
    /// A reference to a S3 bucket.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub s3: Option<S3ConnectionDef>,
    /// Settings for the Coordinator Role/Process.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coordinators: Option<Role<TrinoConfig>>,
    /// Settings for the Worker Role/Process.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workers: Option<Role<TrinoConfig>>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GlobalTrinoConfig {
    /// Only affects client connections.
    /// This setting controls:
    /// - If TLS encryption is used at all
    /// - Which cert the servers should use to authenticate themselves against the client
    #[serde(default = "tls_default", skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsSecretClass>,
    /// Only affects internal communication. Use mutual verification between Trino nodes
    /// This setting controls:
    /// - Which cert the servers should use to authenticate themselves against other servers
    /// - Which ca.crt to use when validating the other server
    #[serde(default = "tls_default", skip_serializing_if = "Option::is_none")]
    pub internal_tls: Option<TlsSecretClass>,
}

impl Default for GlobalTrinoConfig {
    fn default() -> Self {
        GlobalTrinoConfig {
            tls: tls_default(),
            internal_tls: tls_default(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TlsSecretClass {
    pub secret_class: String,
}

fn tls_default() -> Option<TlsSecretClass> {
    Some(TlsSecretClass {
        secret_class: TLS_DEFAULT_SECRET_CLASS.to_string(),
    })
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
        let authentication_enabled: bool = resource.get_authentication().is_some();
        let client_tls_enabled: bool = resource.get_client_tls().is_some();

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
                // coordinator or worker
                result.insert(
                    COORDINATOR.to_string(),
                    Some((role_name == TrinoRole::Coordinator.to_string()).to_string()),
                );
                // TrinoConfig properties
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
                // If authentication is enabled
                // - client TLS is required (default to "tls" if not provided)
                // - internal shared secret must be set
                if authentication_enabled || client_tls_enabled {
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
                        Some(format!("{}/{}", STACKABLE_CLIENT_TLS_DIR, "keystore.p12")),
                    );
                    result.insert(
                        HTTP_SERVER_HTTPS_KEYSTORE_KEY.to_string(),
                        Some(STACKABLE_TLS_STORE_PASSWORD.to_string()),
                    );
                    result.insert(
                        HTTP_SERVER_TRUSTSTORE_PATH.to_string(),
                        Some(format!("{}/{}", STACKABLE_CLIENT_TLS_DIR, "truststore.p12")),
                    );
                    result.insert(
                        HTTP_SERVER_HTTPS_TRUSTSTORE_KEY.to_string(),
                        Some(STACKABLE_TLS_STORE_PASSWORD.to_string()),
                    );

                    if authentication_enabled {
                        // Setting the internal secret is mandatory for authentication
                        result.insert(
                            INTERNAL_COMMUNICATION_SHARED_SECRET.to_string(),
                            Some(format!("${{ENV:{secret}}}", secret = ENV_INTERNAL_SECRET)),
                        );
                        // For Authentication we have to differentiate several options here:
                        // - Authentication PASSWORD: FILE | LDAP (works only with HTTPS enabled)
                        // - requires both internal secret and client TLS to be configured
                        if role_name == TrinoRole::Coordinator.to_string() {
                            // password ui login
                            result.insert(
                                HTTP_SERVER_AUTHENTICATION_TYPE.to_string(),
                                Some(HTTP_SERVER_AUTHENTICATION_TYPE_PASSWORD.to_string()),
                            );
                        }
                    }
                }

                // If internal TLS is enabled
                if resource.get_internal_tls().is_some() {
                    if !authentication_enabled && !client_tls_enabled {
                        // The first two properties (HTTPS_ENABLED, HTTPS_PORT) may be set above for client TLS. We only need to set
                        // them here if client tls (and/or authentication) are not enabled.
                        // In the case of only internal TLS is activated (meaning no authentication
                        // and client TLS is set) we have to activate HTTPS and allow insecure
                        // communications via HTTP
                        result.insert(
                            HTTP_SERVER_HTTPS_ENABLED.to_string(),
                            Some(true.to_string()),
                        );
                        result.insert(
                            HTTP_SERVER_HTTPS_PORT.to_string(),
                            Some(HTTPS_PORT.to_string()),
                        );
                        result.insert(
                            HTTP_SERVER_AUTHENTICATION_ALLOW_INSECURE_OVER_HTTP.to_string(),
                            Some("true".to_string()),
                        );
                        // additionally we have to set the https keystores (only if no
                        // authentication or client tls is required! Trino complains otherwise
                        // about wrong HTTPS configuration
                        result.insert(
                            HTTP_SERVER_KEYSTORE_PATH.to_string(),
                            Some(format!("{}/{}", STACKABLE_INTERNAL_TLS_DIR, "keystore.p12")),
                        );
                        result.insert(
                            HTTP_SERVER_HTTPS_KEYSTORE_KEY.to_string(),
                            Some(STACKABLE_TLS_STORE_PASSWORD.to_string()),
                        );
                        result.insert(
                            HTTP_SERVER_TRUSTSTORE_PATH.to_string(),
                            Some(format!(
                                "{}/{}",
                                STACKABLE_INTERNAL_TLS_DIR, "truststore.p12"
                            )),
                        );
                        result.insert(
                            HTTP_SERVER_HTTPS_TRUSTSTORE_KEY.to_string(),
                            Some(STACKABLE_TLS_STORE_PASSWORD.to_string()),
                        );
                    }
                    result.insert(
                        INTERNAL_COMMUNICATION_SHARED_SECRET.to_string(),
                        Some(format!("${{ENV:{secret}}}", secret = ENV_INTERNAL_SECRET)),
                    );
                    result.insert(
                        INTERNAL_COMMUNICATION_HTTPS_KEYSTORE_PATH.to_string(),
                        Some(format!("{}/keystore.p12", STACKABLE_INTERNAL_TLS_DIR)),
                    );
                    result.insert(
                        INTERNAL_COMMUNICATION_HTTPS_KEYSTORE_KEY.to_string(),
                        Some(STACKABLE_TLS_STORE_PASSWORD.to_string()),
                    );
                    result.insert(
                        INTERNAL_COMMUNICATION_HTTPS_TRUSTSTORE_PATH.to_string(),
                        Some(format!("{}/truststore.p12", STACKABLE_INTERNAL_TLS_DIR)),
                    );
                    result.insert(
                        INTERNAL_COMMUNICATION_HTTPS_TRUSTSTORE_KEY.to_string(),
                        Some(STACKABLE_TLS_STORE_PASSWORD.to_string()),
                    );
                    result.insert(
                        NODE_INTERNAL_ADDRESS_SOURCE.to_string(),
                        Some(NODE_INTERNAL_ADDRESS_SOURCE_FQDN.to_string()),
                    );
                }
            }
            PASSWORD_AUTHENTICATOR_PROPERTIES => {
                if authentication_enabled {
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

    /// Returns the provided docker image e.g. 377-stackable0
    pub fn image_version(&self) -> Result<&str, Error> {
        self.spec
            .version
            .as_deref()
            .context(ObjectHasNoVersionSnafu)
    }

    /// Returns our semver representation for product config e.g. 377.0.0
    pub fn product_version(&self) -> Result<String, Error> {
        let image_version = self.image_version()?;
        let product_version = image_version
            .split('-')
            .collect::<Vec<_>>()
            .first()
            .cloned()
            .with_context(|| TrinoProductVersionSnafu {
                image_version: image_version.to_string(),
            })?;
        Ok(format!("{}.0.0", product_version))
    }

    /// Returns user provided authentication settings
    pub fn get_authentication(&self) -> Option<&Authentication> {
        let spec: &TrinoClusterSpec = &self.spec;
        spec.authentication.as_ref()
    }

    /// Return user provided client TLS settings
    pub fn get_client_tls(&self) -> Option<&TlsSecretClass> {
        let spec: &TrinoClusterSpec = &self.spec;
        spec.config.tls.as_ref()
    }

    /// Return if client TLS should be set depending on settings for authentication and client TLS.
    pub fn tls_enabled(&self) -> bool {
        self.get_authentication().is_some() || self.get_client_tls().is_some()
    }

    /// Return user provided internal TLS settings.
    pub fn get_internal_tls(&self) -> Option<&TlsSecretClass> {
        let spec: &TrinoClusterSpec = &self.spec;
        spec.config.internal_tls.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_tls() {
        let input = r#"
        apiVersion: trino.stackable.tech/v1alpha1
        kind: TrinoCluster
        metadata:
          name: simple-trino
        spec:
          version: abc
        "#;
        let trino: TrinoCluster = serde_yaml::from_str(input).expect("illegal test input");
        assert_eq!(
            trino.get_client_tls().unwrap().secret_class,
            TLS_DEFAULT_SECRET_CLASS.to_string()
        );
        assert_eq!(
            trino.get_internal_tls().unwrap().secret_class,
            TLS_DEFAULT_SECRET_CLASS.to_string()
        );

        let input = r#"
        apiVersion: trino.stackable.tech/v1alpha1
        kind: TrinoCluster
        metadata:
          name: simple-trino
        spec:
          version: abc
          config:
            tls:
              secretClass: simple-trino-client-tls
        "#;
        let trino: TrinoCluster = serde_yaml::from_str(input).expect("illegal test input");
        assert_eq!(
            trino.get_client_tls().unwrap().secret_class,
            "simple-trino-client-tls".to_string()
        );
        assert_eq!(
            trino.get_internal_tls().unwrap().secret_class,
            TLS_DEFAULT_SECRET_CLASS.to_string()
        );

        let input = r#"
        apiVersion: trino.stackable.tech/v1alpha1
        kind: TrinoCluster
        metadata:
          name: simple-trino
        spec:
          version: abc
          config:
            tls: null
        "#;
        let trino: TrinoCluster = serde_yaml::from_str(input).expect("illegal test input");
        assert_eq!(trino.get_client_tls(), None);
        assert_eq!(
            trino.get_internal_tls().unwrap().secret_class,
            TLS_DEFAULT_SECRET_CLASS.to_string()
        );

        let input = r#"
        apiVersion: trino.stackable.tech/v1alpha1
        kind: TrinoCluster
        metadata:
          name: simple-trino
        spec:
          version: abc
          config:
            internalTls:
              secretClass: simple-trino-internal-tls
        "#;
        let trino: TrinoCluster = serde_yaml::from_str(input).expect("illegal test input");
        assert_eq!(
            trino.get_client_tls().unwrap().secret_class,
            TLS_DEFAULT_SECRET_CLASS.to_string()
        );
        assert_eq!(
            trino.get_internal_tls().unwrap().secret_class,
            "simple-trino-internal-tls"
        );
    }

    #[test]
    fn test_internal_tls() {
        let input = r#"
        apiVersion: trino.stackable.tech/v1alpha1
        kind: TrinoCluster
        metadata:
          name: simple-trino
        spec:
          version: abc
        "#;
        let trino: TrinoCluster = serde_yaml::from_str(input).expect("illegal test input");
        assert_eq!(
            trino.get_internal_tls().unwrap().secret_class,
            TLS_DEFAULT_SECRET_CLASS.to_string()
        );
        assert_eq!(
            trino.get_client_tls().unwrap().secret_class,
            TLS_DEFAULT_SECRET_CLASS
        );

        let input = r#"
        apiVersion: trino.stackable.tech/v1alpha1
        kind: TrinoCluster
        metadata:
          name: simple-trino
        spec:
          version: abc
          config:
            internalTls:
              secretClass: simple-trino-internal-tls
        "#;
        let trino: TrinoCluster = serde_yaml::from_str(input).expect("illegal test input");
        assert_eq!(
            trino.get_internal_tls().unwrap().secret_class,
            "simple-trino-internal-tls".to_string()
        );
        assert_eq!(
            trino.get_client_tls().unwrap().secret_class,
            TLS_DEFAULT_SECRET_CLASS
        );

        let input = r#"
        apiVersion: trino.stackable.tech/v1alpha1
        kind: TrinoCluster
        metadata:
          name: simple-trino
        spec:
          version: abc
          config:
            tls:
              secretClass: simple-trino-client-tls
            internalTls: null
        "#;
        let trino: TrinoCluster = serde_yaml::from_str(input).expect("illegal test input");
        assert_eq!(trino.get_internal_tls(), None);
        assert_eq!(
            trino.get_client_tls().unwrap().secret_class,
            "simple-trino-client-tls"
        );
    }
}
