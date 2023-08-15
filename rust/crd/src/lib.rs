pub mod affinity;
pub mod authentication;
pub mod catalog;
pub mod discovery;

use crate::discovery::TrinoPodRef;

use affinity::get_affinity;
use catalog::TrinoCatalog;
use serde::{Deserialize, Serialize};
use snafu::{OptionExt, ResultExt, Snafu};

use crate::authentication::TrinoAuthenticationClassRef;
use stackable_operator::{
    commons::{
        affinity::StackableAffinity,
        cluster_operation::ClusterOperation,
        opa::OpaConfig,
        product_image_selection::ProductImage,
        resources::{
            CpuLimitsFragment, MemoryLimitsFragment, NoRuntimeLimits, NoRuntimeLimitsFragment,
            PvcConfig, PvcConfigFragment, Resources, ResourcesFragment,
        },
    },
    config::{
        fragment::Fragment,
        fragment::{self, ValidationError},
        merge::Merge,
    },
    k8s_openapi::apimachinery::pkg::{api::resource::Quantity, apis::meta::v1::LabelSelector},
    kube::{runtime::reflector::ObjectRef, CustomResource, ResourceExt},
    product_config_utils::{ConfigError, Configuration},
    product_logging,
    product_logging::spec::Logging,
    role_utils::{Role, RoleGroup, RoleGroupRef},
    schemars::{self, JsonSchema},
    status::condition::{ClusterCondition, HasStatusCondition},
};
use std::{collections::BTreeMap, str::FromStr};
use strum::{Display, EnumIter, EnumString, IntoEnumIterator};

pub const APP_NAME: &str = "trino";
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
pub const ACCESS_CONTROL_PROPERTIES: &str = "access-control.properties";
pub const JVM_SECURITY_PROPERTIES: &str = "security.properties";
// node.properties
pub const NODE_ENVIRONMENT: &str = "node.environment";
// config.properties
pub const COORDINATOR: &str = "coordinator";
pub const DISCOVERY_URI: &str = "discovery.uri";
pub const HTTP_SERVER_HTTP_PORT: &str = "http-server.http.port";
pub const QUERY_MAX_MEMORY: &str = "query.max-memory";
pub const QUERY_MAX_MEMORY_PER_NODE: &str = "query.max-memory-per-node";
// - server tls
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
// log.properties
pub const IO_TRINO: &str = "io.trino";
// jvm.config
pub const METRICS_PORT_PROPERTY: &str = "metricsPort";
// directories
pub const CONFIG_DIR_NAME: &str = "/stackable/config";
pub const RW_CONFIG_DIR_NAME: &str = "/stackable/rwconfig";
pub const DATA_DIR_NAME: &str = "/stackable/data";
pub const S3_SECRET_DIR_NAME: &str = "/stackable/secrets";
pub const STACKABLE_SERVER_TLS_DIR: &str = "/stackable/server_tls";
pub const STACKABLE_CLIENT_TLS_DIR: &str = "/stackable/client_tls";
pub const STACKABLE_INTERNAL_TLS_DIR: &str = "/stackable/internal_tls";
pub const STACKABLE_MOUNT_SERVER_TLS_DIR: &str = "/stackable/mount_server_tls";
pub const STACKABLE_MOUNT_CLIENT_TLS_DIR: &str = "/stackable/mount_client_tls";
pub const STACKABLE_MOUNT_INTERNAL_TLS_DIR: &str = "/stackable/mount_internal_tls";
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
// Logging
pub const LOG_FORMAT: &str = "log.format";
pub const LOG_PATH: &str = "log.path";
pub const LOG_COMPRESSION: &str = "log.compression";
pub const LOG_MAX_SIZE: &str = "log.max-size";
pub const LOG_MAX_TOTAL_SIZE: &str = "log.max-total-size";

pub const JVM_HEAP_FACTOR: f32 = 0.8;

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("object has no namespace associated"))]
    NoNamespace,
    #[snafu(display("object has no names"))]
    NoName,
    #[snafu(display("unknown role {role}. Should be one of {roles:?}"))]
    UnknownTrinoRole {
        source: strum::ParseError,
        role: String,
        roles: Vec<String>,
    },
    #[snafu(display("the role {role} is not defined"))]
    CannotRetrieveTrinoRole { role: String },
    #[snafu(display("the role group {role_group} is not defined"))]
    CannotRetrieveTrinoRoleGroup { role_group: String },
    #[snafu(display("fragment validation failure"))]
    FragmentValidationFailure { source: ValidationError },
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
    /// Trino product image to use.
    pub image: ProductImage,
    /// Trino cluster configuration options.
    pub cluster_config: TrinoClusterConfig,
    /// Cluster operations like pause reconciliation or cluster stop.
    #[serde(default)]
    pub cluster_operation: ClusterOperation,
    /// Settings for the Coordinator Role/Process.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coordinators: Option<Role<TrinoConfigFragment>>,
    /// Settings for the Worker Role/Process.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workers: Option<Role<TrinoConfigFragment>>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrinoClusterConfig {
    /// Authentication options for Trino.
    #[serde(default)]
    pub authentication: Vec<TrinoAuthenticationClassRef>,
    /// Authorization options for Trino.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization: Option<TrinoAuthorization>,
    /// [LabelSelector](https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#label-selectors) selecting the Catalogs
    /// to include in the Trino instance.
    pub catalog_label_selector: LabelSelector,
    /// TLS configuration options for server and internal communication.
    #[serde(default)]
    pub tls: TrinoTls,
    /// Name of the Vector aggregator discovery ConfigMap.
    /// It must contain the key `ADDRESS` with the address of the Vector aggregator.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vector_aggregator_config_map_name: Option<String>,
    /// In the future this setting will control, which ListenerClass <https://docs.stackable.tech/home/stable/listener-operator/listenerclass.html>
    /// will be used to expose the service.
    /// Currently only a subset of the ListenerClasses are supported by choosing the type of the created Services
    /// by looking at the ListenerClass name specified,
    /// In a future release support for custom ListenerClasses will be introduced without a breaking change:
    ///
    /// * cluster-internal: Use a ClusterIP service
    ///
    /// * external-unstable: Use a NodePort service
    ///
    /// * external-stable: Use a LoadBalancer service
    #[serde(default)]
    pub listener_class: CurrentlySupportedListenerClasses,
}

// TODO: Temporary solution until listener-operator is finished
#[derive(Clone, Debug, Default, Display, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum CurrentlySupportedListenerClasses {
    #[default]
    #[serde(rename = "cluster-internal")]
    ClusterInternal,
    #[serde(rename = "external-unstable")]
    ExternalUnstable,
    #[serde(rename = "external-stable")]
    ExternalStable,
}

impl CurrentlySupportedListenerClasses {
    pub fn k8s_service_type(&self) -> String {
        match self {
            CurrentlySupportedListenerClasses::ClusterInternal => "ClusterIP".to_string(),
            CurrentlySupportedListenerClasses::ExternalUnstable => "NodePort".to_string(),
            CurrentlySupportedListenerClasses::ExternalStable => "LoadBalancer".to_string(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrinoAuthorization {
    /// The discovery ConfigMap name of the OPA cluster (usually the same as the OPA cluster name).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub opa: Option<OpaConfig>,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrinoTls {
    /// Only affects client connections.
    /// This setting controls:
    /// - If TLS encryption is used at all
    /// - Which cert the servers should use to authenticate themselves against the client
    #[serde(
        default = "tls_secret_class_default",
        skip_serializing_if = "Option::is_none"
    )]
    pub server_secret_class: Option<String>,
    /// Only affects internal communication. Use mutual verification between Trino nodes
    /// This setting controls:
    /// - Which cert the servers should use to authenticate themselves against other servers
    /// - Which ca.crt to use when validating the other server
    #[serde(
        default = "tls_secret_class_default",
        skip_serializing_if = "Option::is_none"
    )]
    pub internal_secret_class: Option<String>,
}

impl Default for TrinoTls {
    fn default() -> Self {
        TrinoTls {
            server_secret_class: tls_secret_class_default(),
            internal_secret_class: tls_secret_class_default(),
        }
    }
}

fn tls_secret_class_default() -> Option<String> {
    Some(TLS_DEFAULT_SECRET_CLASS.to_string())
}

#[derive(
    Clone,
    Debug,
    Deserialize,
    Display,
    EnumIter,
    Eq,
    Hash,
    JsonSchema,
    PartialEq,
    Serialize,
    EnumString,
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

#[derive(Clone, Debug, Default, JsonSchema, PartialEq, Fragment)]
#[fragment_attrs(
    derive(
        Clone,
        Debug,
        Default,
        Deserialize,
        Merge,
        JsonSchema,
        PartialEq,
        Serialize
    ),
    serde(rename_all = "camelCase")
)]
pub struct TrinoStorageConfig {
    #[fragment_attrs(serde(default))]
    pub data: PvcConfig,
}

#[derive(
    Clone,
    Debug,
    Deserialize,
    Display,
    Eq,
    EnumIter,
    Hash,
    JsonSchema,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
)]
#[serde(rename_all = "kebab-case")]
#[strum(serialize_all = "kebab-case")]
pub enum Container {
    // init
    Prepare,
    // sidecar
    Vector,
    // sidecar
    PasswordFileUpdater,
    // main
    Trino,
}

#[derive(Clone, Debug, Default, Fragment, JsonSchema, PartialEq)]
#[fragment_attrs(
    derive(
        Clone,
        Debug,
        Default,
        Deserialize,
        Merge,
        JsonSchema,
        PartialEq,
        Serialize
    ),
    serde(rename_all = "camelCase")
)]
pub struct TrinoConfig {
    // config.properties
    pub query_max_memory: Option<String>,
    pub query_max_memory_per_node: Option<String>,
    #[fragment_attrs(serde(default))]
    pub logging: Logging<Container>,
    #[fragment_attrs(serde(default))]
    pub resources: Resources<TrinoStorageConfig, NoRuntimeLimits>,
    #[fragment_attrs(serde(default))]
    pub affinity: StackableAffinity,
}

impl TrinoConfig {
    fn default_config(
        cluster_name: &str,
        role: &TrinoRole,
        trino_catalogs: &[TrinoCatalog],
    ) -> TrinoConfigFragment {
        let (cpu_min, cpu_max, memory) = match role {
            TrinoRole::Coordinator => ("500m", "2", "4Gi"),
            TrinoRole::Worker => ("1", "4", "4Gi"),
        };

        TrinoConfigFragment {
            logging: product_logging::spec::default_logging(),
            affinity: get_affinity(cluster_name, role, trino_catalogs),
            resources: ResourcesFragment {
                cpu: CpuLimitsFragment {
                    min: Some(Quantity(cpu_min.to_string())),
                    max: Some(Quantity(cpu_max.to_string())),
                },
                memory: MemoryLimitsFragment {
                    limit: Some(Quantity(memory.to_string())),
                    runtime_limits: NoRuntimeLimitsFragment {},
                },
                storage: TrinoStorageConfigFragment {
                    data: PvcConfigFragment {
                        capacity: Some(Quantity("1Gi".to_owned())),
                        storage_class: None,
                        selectors: None,
                    },
                },
            },
            ..TrinoConfigFragment::default()
        }
    }
}

impl Configuration for TrinoConfigFragment {
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
        let authentication_enabled = resource.authentication_enabled();
        let server_tls_enabled: bool = resource.get_server_tls().is_some();
        let internal_tls_enabled: bool = resource.get_internal_tls().is_some();

        match file {
            NODE_PROPERTIES => {
                // The resource name is alphanumeric and may have "-" characters
                // The Trino node environment is bound to alphanumeric lowercase and "_" characters
                // and must start with alphanumeric (which is the case for resource names as well?)
                // see https://trino.io/docs/current/installation/deployment.html
                let node_env = resource.name_any().to_ascii_lowercase().replace('-', "_");
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

                // disable http-request logs
                result.insert(
                    "http-server.log.enabled".to_string(),
                    Some("false".to_string()),
                );

                // Always use the internal secret (base64)
                result.insert(
                    INTERNAL_COMMUNICATION_SHARED_SECRET.to_string(),
                    Some(format!("${{ENV:{secret}}}", secret = ENV_INTERNAL_SECRET)),
                );

                // If authentication is enabled and client tls is explicitly deactivated we error out
                // Therefore from here on we can use resource.get_server_tls() as the only source
                // of truth when enabling client TLS.
                if authentication_enabled && !server_tls_enabled {
                    return Err(ConfigError::InvalidConfiguration {
                        reason:
                            "Trino requires client TLS to be enabled if any authentication method is enabled! TLS was set to null. \
                             Please set 'spec.clusterConfig.tls.secretClass' or use the provided default value.".to_string(),
                    });
                }

                if server_tls_enabled || internal_tls_enabled {
                    // enable TLS
                    result.insert(
                        HTTP_SERVER_HTTPS_ENABLED.to_string(),
                        Some(true.to_string()),
                    );
                    // via https port
                    result.insert(
                        HTTP_SERVER_HTTPS_PORT.to_string(),
                        Some(HTTPS_PORT.to_string()),
                    );

                    let tls_store_dir = if server_tls_enabled {
                        STACKABLE_SERVER_TLS_DIR
                    } else {
                        // allow insecure communication
                        result.insert(
                            HTTP_SERVER_AUTHENTICATION_ALLOW_INSECURE_OVER_HTTP.to_string(),
                            Some("true".to_string()),
                        );
                        // via the http port
                        result.insert(
                            HTTP_SERVER_HTTP_PORT.to_string(),
                            Some(HTTP_PORT.to_string()),
                        );

                        STACKABLE_INTERNAL_TLS_DIR
                    };

                    result.insert(
                        HTTP_SERVER_KEYSTORE_PATH.to_string(),
                        Some(format!("{}/{}", tls_store_dir, "keystore.p12")),
                    );
                    result.insert(
                        HTTP_SERVER_HTTPS_KEYSTORE_KEY.to_string(),
                        Some(STACKABLE_TLS_STORE_PASSWORD.to_string()),
                    );
                    result.insert(
                        HTTP_SERVER_TRUSTSTORE_PATH.to_string(),
                        Some(format!("{}/{}", tls_store_dir, "truststore.p12")),
                    );
                    result.insert(
                        HTTP_SERVER_HTTPS_TRUSTSTORE_KEY.to_string(),
                        Some(STACKABLE_TLS_STORE_PASSWORD.to_string()),
                    );
                }

                if internal_tls_enabled {
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
            LOG_PROPERTIES => {}
            _ => {}
        }

        Ok(result)
    }
}

impl TrinoCluster {
    /// Returns the name of the cluster and raises an Error if the name is not set.
    pub fn name_r(&self) -> Result<String, Error> {
        self.metadata.name.to_owned().context(NoNameSnafu)
    }

    /// Returns the namespace of the cluster and raises an Error if the name is not set.
    pub fn namespace_r(&self) -> Result<String, Error> {
        self.metadata.namespace.to_owned().context(NoNamespaceSnafu)
    }

    pub fn role_service_name(&self, role: &TrinoRole) -> Result<String, Error> {
        Ok(format!("{}-{}", self.name_r()?, role))
    }

    pub fn role_service_fqdn(&self, role: &TrinoRole) -> Result<String, Error> {
        Ok(format!(
            "{}.{}.svc.cluster.local",
            self.role_service_name(role)?,
            self.namespace_r()?
        ))
    }

    /// Returns a reference to the role. Raises an error if the role is not defined.
    pub fn role(&self, role_variant: &TrinoRole) -> Result<&Role<TrinoConfigFragment>, Error> {
        match role_variant {
            TrinoRole::Coordinator => self.spec.coordinators.as_ref(),
            TrinoRole::Worker => self.spec.workers.as_ref(),
        }
        .with_context(|| CannotRetrieveTrinoRoleSnafu {
            role: role_variant.to_string(),
        })
    }

    /// Returns a reference to the role group. Raises an error if the role or role group are not defined.
    pub fn rolegroup(
        &self,
        rolegroup_ref: &RoleGroupRef<TrinoCluster>,
    ) -> Result<&RoleGroup<TrinoConfigFragment>, Error> {
        let role_variant =
            TrinoRole::from_str(&rolegroup_ref.role).with_context(|_| UnknownTrinoRoleSnafu {
                role: rolegroup_ref.role.to_owned(),
                roles: TrinoRole::roles(),
            })?;
        let role = self.role(&role_variant)?;
        role.role_groups
            .get(&rolegroup_ref.role_group)
            .with_context(|| CannotRetrieveTrinoRoleGroupSnafu {
                role_group: rolegroup_ref.role_group.to_owned(),
            })
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

    /// Returns user provided authentication settings
    pub fn get_authentication(&self) -> &Vec<TrinoAuthenticationClassRef> {
        &self.spec.cluster_config.authentication
    }

    /// Check if any authentication settings are provided
    pub fn authentication_enabled(&self) -> bool {
        let spec: &TrinoClusterSpec = &self.spec;
        !spec.cluster_config.authentication.is_empty()
    }

    /// Return user provided server TLS settings
    pub fn get_server_tls(&self) -> Option<&str> {
        let spec: &TrinoClusterSpec = &self.spec;
        spec.cluster_config.tls.server_secret_class.as_deref()
    }

    /// Return if client TLS should be set depending on settings for authentication and client TLS.
    pub fn tls_enabled(&self) -> bool {
        self.authentication_enabled() || self.get_server_tls().is_some()
    }

    /// Return user provided internal TLS settings.
    pub fn get_internal_tls(&self) -> Option<&str> {
        let spec: &TrinoClusterSpec = &self.spec;
        spec.cluster_config.tls.internal_secret_class.as_deref()
    }

    /// Returns if the HTTP port should be exposed
    pub fn expose_http_port(&self) -> bool {
        self.get_server_tls().is_none()
    }

    /// Returns if the HTTPS port should be exposed
    pub fn expose_https_port(&self) -> bool {
        self.get_server_tls().is_some()
    }

    /// Retrieve and merge resource configs for role and role groups
    pub fn merged_config(
        &self,
        role: &TrinoRole,
        rolegroup_ref: &RoleGroupRef<TrinoCluster>,
        trino_catalogs: &[TrinoCatalog],
    ) -> Result<TrinoConfig, Error> {
        // Initialize the result with all default values as baseline
        let conf_defaults = TrinoConfig::default_config(&self.name_any(), role, trino_catalogs);

        let role = self.role(role)?;

        // Retrieve role resource config
        let mut conf_role = role.config.config.to_owned();

        // Retrieve rolegroup specific resource config
        let mut conf_rolegroup = self.rolegroup(rolegroup_ref)?.config.config.clone();

        if let Some(RoleGroup {
            selector: Some(selector),
            ..
        }) = role.role_groups.get(&rolegroup_ref.role_group)
        {
            // Migrate old `selector` attribute, see ADR 26 affinities.
            // TODO Can be removed after support for the old `selector` field is dropped.
            #[allow(deprecated)]
            conf_rolegroup.affinity.add_legacy_selector(selector);
        }

        // Merge more specific configs into default config
        // Hierarchy is:
        // 1. RoleGroup
        // 2. Role
        // 3. Default
        conf_role.merge(&conf_defaults);
        conf_rolegroup.merge(&conf_role);

        tracing::debug!("Merged config: {:?}", conf_rolegroup);
        fragment::validate(conf_rolegroup).context(FragmentValidationFailureSnafu)
    }
}

#[derive(Clone, Default, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrinoClusterStatus {
    #[serde(default)]
    pub conditions: Vec<ClusterCondition>,
}

impl HasStatusCondition for TrinoCluster {
    fn conditions(&self) -> Vec<ClusterCondition> {
        match &self.status {
            Some(status) => status.conditions.clone(),
            None => vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_tls() {
        let input = r#"
        apiVersion: trino.stackable.tech/v1alpha1
        kind: TrinoCluster
        metadata:
          name: simple-trino
        spec:
          image:
            productVersion: "414"
          clusterConfig:
            catalogLabelSelector: {}
        "#;
        let trino: TrinoCluster = serde_yaml::from_str(input).expect("illegal test input");
        assert_eq!(trino.get_server_tls(), Some(TLS_DEFAULT_SECRET_CLASS));
        assert_eq!(trino.get_internal_tls(), Some(TLS_DEFAULT_SECRET_CLASS));

        let input = r#"
        apiVersion: trino.stackable.tech/v1alpha1
        kind: TrinoCluster
        metadata:
          name: simple-trino
        spec:
          image:
            productVersion: "414"
          clusterConfig:
            catalogLabelSelector: {}
            tls:
              serverSecretClass: simple-trino-server-tls
        "#;
        let trino: TrinoCluster = serde_yaml::from_str(input).expect("illegal test input");
        assert_eq!(trino.get_server_tls(), Some("simple-trino-server-tls"));
        assert_eq!(trino.get_internal_tls(), Some(TLS_DEFAULT_SECRET_CLASS));

        let input = r#"
        apiVersion: trino.stackable.tech/v1alpha1
        kind: TrinoCluster
        metadata:
          name: simple-trino
        spec:
          image:
            productVersion: "414"
          clusterConfig:
            catalogLabelSelector: {}
            tls:
              serverSecretClass: null
              internalSecretClass: null
        "#;
        let trino: TrinoCluster = serde_yaml::from_str(input).expect("illegal test input");
        assert_eq!(trino.get_server_tls(), None);
        assert_eq!(trino.get_internal_tls(), None);

        let input = r#"
        apiVersion: trino.stackable.tech/v1alpha1
        kind: TrinoCluster
        metadata:
          name: simple-trino
        spec:
          image:
            productVersion: "414"
          clusterConfig:
            catalogLabelSelector: {}
            tls:
              internalSecretClass: simple-trino-internal-tls
        "#;
        let trino: TrinoCluster = serde_yaml::from_str(input).expect("illegal test input");
        assert_eq!(trino.get_server_tls(), Some(TLS_DEFAULT_SECRET_CLASS));
        assert_eq!(trino.get_internal_tls(), Some("simple-trino-internal-tls"));
    }

    #[test]
    fn test_internal_tls() {
        let input = r#"
        apiVersion: trino.stackable.tech/v1alpha1
        kind: TrinoCluster
        metadata:
          name: simple-trino
        spec:
          image:
            productVersion: "414"
          clusterConfig:
            catalogLabelSelector: {}
        "#;
        let trino: TrinoCluster = serde_yaml::from_str(input).expect("illegal test input");
        assert_eq!(trino.get_internal_tls(), Some(TLS_DEFAULT_SECRET_CLASS));
        assert_eq!(trino.get_server_tls(), Some(TLS_DEFAULT_SECRET_CLASS));

        let input = r#"
        apiVersion: trino.stackable.tech/v1alpha1
        kind: TrinoCluster
        metadata:
          name: simple-trino
        spec:
          image:
            productVersion: "414"
          clusterConfig:
            catalogLabelSelector: {}
            tls:
              internalSecretClass: simple-trino-internal-tls
        "#;
        let trino: TrinoCluster = serde_yaml::from_str(input).expect("illegal test input");
        assert_eq!(trino.get_internal_tls(), Some("simple-trino-internal-tls"));
        assert_eq!(trino.get_server_tls(), Some(TLS_DEFAULT_SECRET_CLASS));

        let input = r#"
        apiVersion: trino.stackable.tech/v1alpha1
        kind: TrinoCluster
        metadata:
          name: simple-trino
        spec:
          image:
            productVersion: "414"
          clusterConfig:
            catalogLabelSelector: {}
            tls:
              serverSecretClass: simple-trino-server-tls
              internalSecretClass: null
        "#;
        let trino: TrinoCluster = serde_yaml::from_str(input).expect("illegal test input");
        assert_eq!(trino.get_internal_tls(), None);
        assert_eq!(trino.get_server_tls(), Some("simple-trino-server-tls"));
    }
}
