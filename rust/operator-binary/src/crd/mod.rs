pub mod affinity;
pub mod authentication;
pub mod catalog;
pub mod discovery;

use std::{collections::BTreeMap, ops::Div, str::FromStr};

use affinity::get_affinity;
use serde::{Deserialize, Serialize};
use snafu::{OptionExt, ResultExt, Snafu};
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
        fragment::{self, Fragment, ValidationError},
        merge::Merge,
    },
    crd::authentication::core,
    k8s_openapi::apimachinery::pkg::{api::resource::Quantity, apis::meta::v1::LabelSelector},
    kube::{CustomResource, ResourceExt, runtime::reflector::ObjectRef},
    memory::{BinaryMultiple, MemoryQuantity},
    product_config_utils::{Configuration, Error as ConfigError},
    product_logging::{self, spec::Logging},
    role_utils::{
        CommonConfiguration, GenericRoleConfig, JavaCommonConfig, Role, RoleGroup, RoleGroupRef,
    },
    schemars::{self, JsonSchema},
    status::condition::{ClusterCondition, HasStatusCondition},
    time::Duration,
    utils::cluster_info::KubernetesClusterInfo,
    versioned::versioned,
};
use strum::{Display, EnumIter, EnumString, IntoEnumIterator};
use v1alpha1::TrinoConfigFragment;

use crate::crd::{discovery::TrinoPodRef, v1alpha1::TrinoCoordinatorRoleConfig};

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
// directories
pub const CONFIG_DIR_NAME: &str = "/stackable/config";
pub const RW_CONFIG_DIR_NAME: &str = "/stackable/rwconfig";
pub const DATA_DIR_NAME: &str = "/stackable/data";
pub const STACKABLE_SERVER_TLS_DIR: &str = "/stackable/server_tls";
pub const STACKABLE_CLIENT_TLS_DIR: &str = "/stackable/client_tls";
pub const STACKABLE_INTERNAL_TLS_DIR: &str = "/stackable/internal_tls";
pub const STACKABLE_LOG_DIR: &str = "/stackable/log";
pub const STACKABLE_MOUNT_SERVER_TLS_DIR: &str = "/stackable/mount_server_tls";
pub const STACKABLE_MOUNT_INTERNAL_TLS_DIR: &str = "/stackable/mount_internal_tls";
pub const SYSTEM_TRUST_STORE: &str = "/etc/pki/java/cacerts";
// store pws
pub const STACKABLE_TLS_STORE_PASSWORD: &str = "changeit";
pub const SYSTEM_TRUST_STORE_PASSWORD: &str = "changeit";
// secret vars
pub const ENV_INTERNAL_SECRET: &str = "INTERNAL_SECRET";
// TLS
pub const TLS_DEFAULT_SECRET_CLASS: &str = "tls";
// Logging
pub const LOG_FORMAT: &str = "log.format";
pub const LOG_PATH: &str = "log.path";
pub const LOG_COMPRESSION: &str = "log.compression";
pub const LOG_MAX_SIZE: &str = "log.max-size";
pub const LOG_MAX_TOTAL_SIZE: &str = "log.max-total-size";
const LOG_FILE_COUNT: u32 = 2;
pub const MAX_TRINO_LOG_FILES_SIZE: MemoryQuantity = MemoryQuantity {
    value: 10.0,
    unit: BinaryMultiple::Mebi,
};

pub const METRICS_SERVICE_SUFFIX: &str = "metrics";

pub const JVM_HEAP_FACTOR: f32 = 0.8;

pub const DEFAULT_COORDINATOR_GRACEFUL_SHUTDOWN_TIMEOUT: Duration =
    Duration::from_minutes_unchecked(15);
pub const DEFAULT_WORKER_GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_minutes_unchecked(60);

/// Corresponds to "shutdown.grace-period", which defaults to 2 min.
/// This seems a bit high, as Pod termination - even with no queries running on the worker -
/// takes at least 4 minutes (see <https://trino.io/docs/current/admin/graceful-shutdown.html>).
/// So we set it to 30 seconds, so the Pod termination takes at least 1 minute.
pub const WORKER_SHUTDOWN_GRACE_PERIOD: Duration = Duration::from_secs(30);

/// Safety puffer to guarantee the graceful shutdown works every time.
pub const WORKER_GRACEFUL_SHUTDOWN_SAFETY_OVERHEAD: Duration = Duration::from_secs(10);

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

#[versioned(version(name = "v1alpha1"), options(skip(from)))]
pub mod versioned {
    /// A Trino cluster stacklet. This resource is managed by the Stackable operator for Trino.
    /// Find more information on how to use it and the resources that the operator generates in the
    /// [operator documentation](DOCS_BASE_URL_PLACEHOLDER/trino/).
    #[versioned(k8s(
        group = "trino.stackable.tech",
        kind = "TrinoCluster",
        plural = "trinoclusters",
        shortname = "trino",
        status = "TrinoClusterStatus",
        namespaced,
        crates(
            kube_core = "stackable_operator::kube::core",
            k8s_openapi = "stackable_operator::k8s_openapi",
            schemars = "stackable_operator::schemars"
        )
    ))]
    #[derive(Clone, CustomResource, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct TrinoClusterSpec {
        // no doc - it's in the struct.
        pub image: ProductImage,

        /// Settings that affect all roles and role groups.
        /// The settings in the `clusterConfig` are cluster wide settings that do not need to be configurable at role or role group level.
        pub cluster_config: TrinoClusterConfig,

        // no doc - it's in the struct.
        #[serde(default)]
        pub cluster_operation: ClusterOperation,

        // no doc - it's in the struct.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub coordinators:
            Option<Role<TrinoConfigFragment, TrinoCoordinatorRoleConfig, JavaCommonConfig>>,

        // no doc - it's in the struct.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub workers: Option<Role<TrinoConfigFragment, GenericRoleConfig, JavaCommonConfig>>,
    }

    // TODO: move generic version to op-rs?
    #[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct TrinoCoordinatorRoleConfig {
        #[serde(flatten)]
        pub common: GenericRoleConfig,

        /// This field controls which [ListenerClass](DOCS_BASE_URL_PLACEHOLDER/listener-operator/listenerclass.html) is used to expose the coordinator.
        #[serde(default = "coordinator_default_listener_class")]
        pub listener_class: String,
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

        /// Time period Pods have to gracefully shut down, e.g. `30m`, `1h` or `2d`. Consult the operator documentation for details.
        #[fragment_attrs(serde(default))]
        pub graceful_shutdown_timeout: Option<Duration>,

        /// Request secret (currently only autoTls certificates) lifetime from the secret operator, e.g. `7d`, or `30d`.
        /// This can be shortened by the `maxCertificateLifetime` setting on the SecretClass issuing the TLS certificate.
        ///
        /// Defaults to `15d` for coordinators (as currently a restart kills all running queries)
        /// and `1d` for workers.
        #[fragment_attrs(serde(default))]
        pub requested_secret_lifetime: Option<Duration>,
    }

    #[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct TrinoClusterConfig {
        /// Authentication options for Trino.
        /// Learn more in the [Trino authentication usage guide](DOCS_BASE_URL_PLACEHOLDER/trino/usage-guide/security#authentication).
        #[serde(default)]
        pub authentication: Vec<core::v1alpha1::ClientAuthenticationDetails>,

        /// Authorization options for Trino.
        /// Learn more in the [Trino authorization usage guide](DOCS_BASE_URL_PLACEHOLDER/trino/usage-guide/security#authorization).
        #[serde(skip_serializing_if = "Option::is_none")]
        pub authorization: Option<TrinoAuthorization>,

        /// [LabelSelector](https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#label-selectors) selecting the Catalogs
        /// to include in the Trino instance.
        pub catalog_label_selector: LabelSelector,

        /// TLS configuration options for server and internal communication.
        #[serde(default)]
        pub tls: TrinoTls,

        /// Name of the Vector aggregator [discovery ConfigMap](DOCS_BASE_URL_PLACEHOLDER/concepts/service_discovery).
        /// It must contain the key `ADDRESS` with the address of the Vector aggregator.
        /// Follow the [logging tutorial](DOCS_BASE_URL_PLACEHOLDER/tutorials/logging-vector-aggregator)
        /// to learn how to configure log aggregation with Vector.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub vector_aggregator_config_map_name: Option<String>,
    }

    #[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct TrinoAuthorization {
        // no doc - it's in the struct.
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

    #[derive(Clone, Default, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct TrinoClusterStatus {
        #[serde(default)]
        pub conditions: Vec<ClusterCondition>,
    }
}

impl Default for v1alpha1::TrinoCoordinatorRoleConfig {
    fn default() -> Self {
        v1alpha1::TrinoCoordinatorRoleConfig {
            listener_class: coordinator_default_listener_class(),
            common: Default::default(),
        }
    }
}

fn coordinator_default_listener_class() -> String {
    "cluster-internal".to_string()
}

impl Default for v1alpha1::TrinoTls {
    fn default() -> Self {
        v1alpha1::TrinoTls {
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
        trino: &v1alpha1::TrinoCluster,
        group_name: impl Into<String>,
    ) -> RoleGroupRef<v1alpha1::TrinoCluster> {
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

    pub fn listener_class_name(&self, trino: &v1alpha1::TrinoCluster) -> Option<String> {
        match self {
            Self::Coordinator => trino
                .spec
                .coordinators
                .to_owned()
                .map(|coordinator| coordinator.role_config.listener_class),
            Self::Worker => None,
        }
    }
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

impl v1alpha1::TrinoConfig {
    fn default_config(
        cluster_name: &str,
        role: &TrinoRole,
        trino_catalogs: &[catalog::v1alpha1::TrinoCatalog],
    ) -> v1alpha1::TrinoConfigFragment {
        let (cpu_min, cpu_max, memory) = match role {
            TrinoRole::Coordinator => ("500m", "2", "4Gi"),
            TrinoRole::Worker => ("1", "4", "4Gi"),
        };
        let graceful_shutdown_timeout = match role {
            TrinoRole::Coordinator => DEFAULT_COORDINATOR_GRACEFUL_SHUTDOWN_TIMEOUT,
            TrinoRole::Worker => DEFAULT_WORKER_GRACEFUL_SHUTDOWN_TIMEOUT,
        };
        let requested_secret_lifetime = match role {
            // TODO: Once Trino supports a HA setup for coordinators we should decrease this!
            // See https://github.com/stackabletech/trino-operator/issues/693
            // and https://github.com/stackabletech/decisions/issues/38 for details
            TrinoRole::Coordinator => Duration::from_days_unchecked(15),
            TrinoRole::Worker => Duration::from_days_unchecked(1),
        };

        v1alpha1::TrinoConfigFragment {
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
                storage: v1alpha1::TrinoStorageConfigFragment {
                    data: PvcConfigFragment {
                        capacity: Some(Quantity("1Gi".to_owned())),
                        storage_class: None,
                        selectors: None,
                    },
                },
            },
            query_max_memory: None,
            query_max_memory_per_node: None,
            graceful_shutdown_timeout: Some(graceful_shutdown_timeout),
            requested_secret_lifetime: Some(requested_secret_lifetime),
        }
    }
}

impl Configuration for v1alpha1::TrinoConfigFragment {
    type Configurable = v1alpha1::TrinoCluster;

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

                // The log format used by Trino
                result.insert(LOG_FORMAT.to_string(), Some("json".to_string()));
                // The path to the log file used by Trino
                result.insert(
                    LOG_PATH.to_string(),
                    Some(format!(
                        "{STACKABLE_LOG_DIR}/{container}/server.airlift.json",
                        container = Container::Trino
                    )),
                );

                // We do not compress. This will result in LOG_MAX_TOTAL_SIZE / LOG_MAX_SIZE files.
                result.insert(LOG_COMPRESSION.to_string(), Some("none".to_string()));

                // The size of one log file
                result.insert(
                    LOG_MAX_SIZE.to_string(),
                    Some(format!(
                        // Trino uses the unit "MB" for MiB.
                        "{}MB",
                        MAX_TRINO_LOG_FILES_SIZE
                            .scale_to(BinaryMultiple::Mebi)
                            .div(LOG_FILE_COUNT as f32)
                            .ceil()
                            .value,
                    )),
                );
                // The maximum size of all logfiles combined
                result.insert(
                    LOG_MAX_TOTAL_SIZE.to_string(),
                    Some(format!(
                        // Trino uses the unit "MB" for MiB.
                        "{}MB",
                        MAX_TRINO_LOG_FILES_SIZE
                            .scale_to(BinaryMultiple::Mebi)
                            .ceil()
                            .value,
                    )),
                );

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
                    return Err(ConfigError::InvalidProductSpecificConfiguration {
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
            ACCESS_CONTROL_PROPERTIES => {}
            _ => {}
        }

        Ok(result)
    }
}

impl v1alpha1::TrinoCluster {
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

    pub fn role_service_fqdn(
        &self,
        role: &TrinoRole,
        cluster_info: &KubernetesClusterInfo,
    ) -> Result<String, Error> {
        Ok(format!(
            "{role_service_name}.{namespace}.svc.{cluster_domain}",
            role_service_name = self.role_service_name(role)?,
            namespace = self.namespace_r()?,
            cluster_domain = cluster_info.cluster_domain
        ))
    }

    /// Returns a reference to the role. Raises an error if the role is not defined.
    pub fn role(
        &self,
        role_variant: &TrinoRole,
    ) -> Result<Role<v1alpha1::TrinoConfigFragment, GenericRoleConfig, JavaCommonConfig>, Error>
    {
        match role_variant {
            TrinoRole::Coordinator => self
                .spec
                .coordinators
                .to_owned()
                .map(extract_role_from_coordinator_config),
            TrinoRole::Worker => self.spec.workers.to_owned(),
        }
        .with_context(|| CannotRetrieveTrinoRoleSnafu {
            role: role_variant.to_string(),
        })
    }

    /// Returns a reference to the role group. Raises an error if the role or role group are not defined.
    pub fn rolegroup(
        &self,
        rolegroup_ref: &RoleGroupRef<v1alpha1::TrinoCluster>,
    ) -> Result<RoleGroup<v1alpha1::TrinoConfigFragment, JavaCommonConfig>, Error> {
        let trino_role =
            TrinoRole::from_str(&rolegroup_ref.role).with_context(|_| UnknownTrinoRoleSnafu {
                role: rolegroup_ref.role.to_owned(),
                roles: TrinoRole::roles(),
            })?;

        let role_variant = self.role(&trino_role)?;

        role_variant
            .role_groups
            .get(&rolegroup_ref.role_group)
            .cloned()
            .with_context(|| CannotRetrieveTrinoRoleGroupSnafu {
                role_group: rolegroup_ref.role_group.to_owned(),
            })
    }

    pub fn generic_role_config(&self, role: &TrinoRole) -> Option<&GenericRoleConfig> {
        match role {
            TrinoRole::Coordinator => self
                .spec
                .coordinators
                .as_ref()
                .map(|c| &c.role_config.common),
            TrinoRole::Worker => self.spec.workers.as_ref().map(|w| &w.role_config),
        }
    }

    pub fn num_workers(&self) -> u16 {
        self.spec
            .workers
            .iter()
            .flat_map(|w| w.role_groups.values())
            .map(|rg| rg.replicas.unwrap_or(1))
            .sum()
    }

    /// Returns the minimal gracefulShutdownTimeout of all the worker rolegroups.
    pub fn min_worker_graceful_shutdown_timeout(&self) -> Duration {
        let role_timeout = self
            .spec
            .workers
            .as_ref()
            .and_then(|w| w.config.config.graceful_shutdown_timeout);
        self.spec
            .workers
            .as_ref()
            .iter()
            .flat_map(|worker| worker.role_groups.values())
            .map(|role_group| {
                role_group
                    .config
                    .config
                    .graceful_shutdown_timeout
                    .unwrap_or(role_timeout.unwrap_or(DEFAULT_WORKER_GRACEFUL_SHUTDOWN_TIMEOUT))
            })
            .min()
            .unwrap_or(DEFAULT_WORKER_GRACEFUL_SHUTDOWN_TIMEOUT)
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
                let role_group_ref = TrinoRole::Coordinator.rolegroup_ref(self, rolegroup_name);
                let ns = ns.clone();
                (0..rolegroup.replicas.unwrap_or(0)).map(move |i| TrinoPodRef {
                    namespace: ns.clone(),
                    role_group_service_name: Self::rolegroup_metrics_service_name(
                        &role_group_ref.object_name(),
                    ),
                    pod_name: format!("{}-{}", role_group_ref.object_name(), i),
                })
            }))
    }

    /// Returns the metrics rolegroup service name `simple-trino-coordinator-default-<METRICS_SERVICE_SUFFIX>`.
    pub fn rolegroup_metrics_service_name(role_group_ref_object_name: &str) -> String {
        format!("{}-{}", role_group_ref_object_name, METRICS_SERVICE_SUFFIX)
    }

    /// Returns user provided authentication settings
    pub fn get_authentication(&self) -> &Vec<core::v1alpha1::ClientAuthenticationDetails> {
        &self.spec.cluster_config.authentication
    }

    /// Check if any authentication settings are provided
    pub fn authentication_enabled(&self) -> bool {
        let spec: &v1alpha1::TrinoClusterSpec = &self.spec;
        !spec.cluster_config.authentication.is_empty()
    }

    pub fn get_opa_config(&self) -> Option<&OpaConfig> {
        self.spec
            .cluster_config
            .authorization
            .as_ref()
            .and_then(|a| a.opa.as_ref())
    }

    /// Return user provided server TLS settings
    pub fn get_server_tls(&self) -> Option<&str> {
        let spec: &v1alpha1::TrinoClusterSpec = &self.spec;
        spec.cluster_config.tls.server_secret_class.as_deref()
    }

    /// Return if client TLS should be set depending on settings for authentication and client TLS.
    pub fn tls_enabled(&self) -> bool {
        self.authentication_enabled() || self.get_server_tls().is_some()
    }

    /// Return user provided internal TLS settings.
    pub fn get_internal_tls(&self) -> Option<&str> {
        let spec: &v1alpha1::TrinoClusterSpec = &self.spec;
        spec.cluster_config.tls.internal_secret_class.as_deref()
    }

    pub fn exposed_port(&self) -> u16 {
        match self.get_server_tls() {
            Some(_) => HTTPS_PORT,
            None => HTTP_PORT,
        }
    }

    pub fn exposed_protocol(&self) -> &str {
        match self.get_server_tls() {
            Some(_) => HTTPS_PORT_NAME,
            None => HTTP_PORT_NAME,
        }
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
        rolegroup_ref: &RoleGroupRef<v1alpha1::TrinoCluster>,
        trino_catalogs: &[catalog::v1alpha1::TrinoCatalog],
    ) -> Result<v1alpha1::TrinoConfig, Error> {
        // Initialize the result with all default values as baseline
        let conf_defaults =
            v1alpha1::TrinoConfig::default_config(&self.name_any(), role, trino_catalogs);

        let role = self.role(role)?;

        // Retrieve role resource config
        let mut conf_role = role.config.config.to_owned();

        // Retrieve rolegroup specific resource config
        let mut conf_rolegroup = self.rolegroup(rolegroup_ref)?.config.config.clone();

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

fn extract_role_from_coordinator_config(
    fragment: Role<TrinoConfigFragment, TrinoCoordinatorRoleConfig, JavaCommonConfig>,
) -> Role<TrinoConfigFragment, GenericRoleConfig, JavaCommonConfig> {
    Role {
        config: CommonConfiguration {
            config: fragment.config.config,
            config_overrides: fragment.config.config_overrides,
            env_overrides: fragment.config.env_overrides,
            cli_overrides: fragment.config.cli_overrides,
            pod_overrides: fragment.config.pod_overrides,
            product_specific_common_config: fragment.config.product_specific_common_config,
        },
        role_config: fragment.role_config.common,
        role_groups: fragment
            .role_groups
            .into_iter()
            .map(|(k, v)| {
                (
                    k,
                    RoleGroup {
                        config: CommonConfiguration {
                            config: v.config.config,
                            config_overrides: v.config.config_overrides,
                            env_overrides: v.config.env_overrides,
                            cli_overrides: v.config.cli_overrides,
                            pod_overrides: v.config.pod_overrides,
                            product_specific_common_config: v.config.product_specific_common_config,
                        },
                        replicas: v.replicas,
                    },
                )
            })
            .collect(),
    }
}

impl HasStatusCondition for v1alpha1::TrinoCluster {
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
            productVersion: "470"
          clusterConfig:
            catalogLabelSelector: {}
        "#;
        let trino: v1alpha1::TrinoCluster =
            serde_yaml::from_str(input).expect("illegal test input");
        assert_eq!(trino.get_server_tls(), Some(TLS_DEFAULT_SECRET_CLASS));
        assert_eq!(trino.get_internal_tls(), Some(TLS_DEFAULT_SECRET_CLASS));

        let input = r#"
        apiVersion: trino.stackable.tech/v1alpha1
        kind: TrinoCluster
        metadata:
          name: simple-trino
        spec:
          image:
            productVersion: "470"
          clusterConfig:
            catalogLabelSelector: {}
            tls:
              serverSecretClass: simple-trino-server-tls
        "#;
        let trino: v1alpha1::TrinoCluster =
            serde_yaml::from_str(input).expect("illegal test input");
        assert_eq!(trino.get_server_tls(), Some("simple-trino-server-tls"));
        assert_eq!(trino.get_internal_tls(), Some(TLS_DEFAULT_SECRET_CLASS));

        let input = r#"
        apiVersion: trino.stackable.tech/v1alpha1
        kind: TrinoCluster
        metadata:
          name: simple-trino
        spec:
          image:
            productVersion: "470"
          clusterConfig:
            catalogLabelSelector: {}
            tls:
              serverSecretClass: null
              internalSecretClass: null
        "#;
        let trino: v1alpha1::TrinoCluster =
            serde_yaml::from_str(input).expect("illegal test input");
        assert_eq!(trino.get_server_tls(), None);
        assert_eq!(trino.get_internal_tls(), None);

        let input = r#"
        apiVersion: trino.stackable.tech/v1alpha1
        kind: TrinoCluster
        metadata:
          name: simple-trino
        spec:
          image:
            productVersion: "470"
          clusterConfig:
            catalogLabelSelector: {}
            tls:
              internalSecretClass: simple-trino-internal-tls
        "#;
        let trino: v1alpha1::TrinoCluster =
            serde_yaml::from_str(input).expect("illegal test input");
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
            productVersion: "470"
          clusterConfig:
            catalogLabelSelector: {}
        "#;
        let trino: v1alpha1::TrinoCluster =
            serde_yaml::from_str(input).expect("illegal test input");
        assert_eq!(trino.get_internal_tls(), Some(TLS_DEFAULT_SECRET_CLASS));
        assert_eq!(trino.get_server_tls(), Some(TLS_DEFAULT_SECRET_CLASS));

        let input = r#"
        apiVersion: trino.stackable.tech/v1alpha1
        kind: TrinoCluster
        metadata:
          name: simple-trino
        spec:
          image:
            productVersion: "470"
          clusterConfig:
            catalogLabelSelector: {}
            tls:
              internalSecretClass: simple-trino-internal-tls
        "#;
        let trino: v1alpha1::TrinoCluster =
            serde_yaml::from_str(input).expect("illegal test input");
        assert_eq!(trino.get_internal_tls(), Some("simple-trino-internal-tls"));
        assert_eq!(trino.get_server_tls(), Some(TLS_DEFAULT_SECRET_CLASS));

        let input = r#"
        apiVersion: trino.stackable.tech/v1alpha1
        kind: TrinoCluster
        metadata:
          name: simple-trino
        spec:
          image:
            productVersion: "470"
          clusterConfig:
            catalogLabelSelector: {}
            tls:
              serverSecretClass: simple-trino-server-tls
              internalSecretClass: null
        "#;
        let trino: v1alpha1::TrinoCluster =
            serde_yaml::from_str(input).expect("illegal test input");
        assert_eq!(trino.get_internal_tls(), None);
        assert_eq!(trino.get_server_tls(), Some("simple-trino-server-tls"));
    }

    #[test]
    fn test_graceful_shutdown_timeout_default() {
        let input = r#"
        apiVersion: trino.stackable.tech/v1alpha1
        kind: TrinoCluster
        metadata:
          name: simple-trino
        spec:
          image:
            productVersion: "470"
          clusterConfig:
            catalogLabelSelector: {}
        "#;
        let trino: v1alpha1::TrinoCluster =
            serde_yaml::from_str(input).expect("illegal test input");
        assert_eq!(
            trino.min_worker_graceful_shutdown_timeout(),
            DEFAULT_WORKER_GRACEFUL_SHUTDOWN_TIMEOUT
        );
    }

    #[test]
    fn test_graceful_shutdown_timeout_on_role() {
        let input = r#"
        apiVersion: trino.stackable.tech/v1alpha1
        kind: TrinoCluster
        metadata:
          name: simple-trino
        spec:
          image:
            productVersion: "470"
          clusterConfig:
            catalogLabelSelector: {}
          workers:
            config:
              gracefulShutdownTimeout: 42h
            roleGroups:
              default:
                replicas: 1
        "#;
        let trino: v1alpha1::TrinoCluster =
            serde_yaml::from_str(input).expect("illegal test input");
        assert_eq!(
            trino.min_worker_graceful_shutdown_timeout(),
            Duration::from_hours_unchecked(42)
        );
    }

    #[test]
    fn test_graceful_shutdown_timeout_on_role_and_rolegroup() {
        let input = r#"
        apiVersion: trino.stackable.tech/v1alpha1
        kind: TrinoCluster
        metadata:
          name: simple-trino
        spec:
          image:
            productVersion: "470"
          clusterConfig:
            catalogLabelSelector: {}
          workers:
            config:
              gracefulShutdownTimeout: 42h
            roleGroups:
              normal:
                replicas: 1
              short:
                replicas: 1
                config:
                  gracefulShutdownTimeout: 5m
              long:
                replicas: 1
                config:
                  gracefulShutdownTimeout: 7d
        "#;
        let trino: v1alpha1::TrinoCluster =
            serde_yaml::from_str(input).expect("illegal test input");
        assert_eq!(
            trino.min_worker_graceful_shutdown_timeout(),
            Duration::from_minutes_unchecked(5)
        );
    }
}
