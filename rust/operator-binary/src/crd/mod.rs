pub mod affinity;
pub mod authentication;
pub mod catalog;
pub mod client_protocol;
pub mod discovery;
pub mod fault_tolerant_execution;

use std::{collections::BTreeMap, str::FromStr};

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
            Resources, ResourcesFragment,
        },
    },
    config::{fragment::Fragment, merge::Merge},
    crd::authentication::core,
    deep_merger::ObjectOverrides,
    k8s_openapi::apimachinery::pkg::{api::resource::Quantity, apis::meta::v1::LabelSelector},
    kube::{CustomResource, runtime::reflector::ObjectRef},
    memory::{BinaryMultiple, MemoryQuantity},
    product_logging::{self, spec::Logging},
    role_utils::{CommonConfiguration, GenericRoleConfig, Role, RoleGroup, RoleGroupRef},
    schemars::{self, JsonSchema},
    shared::time::Duration,
    status::condition::{ClusterCondition, HasStatusCondition},
    v2::{
        config_overrides::KeyValueConfigOverrides, role_utils::JavaCommonConfig,
        types::kubernetes::NamespaceName,
    },
    versioned::versioned,
};
use strum::{Display, EnumIter, EnumString, IntoEnumIterator};

use crate::crd::discovery::TrinoPodRef;

pub type TrinoCoordinatorRoleType = Role<
    v1alpha1::TrinoConfigFragment,
    v1alpha1::TrinoConfigOverrides,
    v1alpha1::TrinoCoordinatorRoleConfig,
    JavaCommonConfig,
>;

pub type TrinoRoleType = Role<
    v1alpha1::TrinoConfigFragment,
    v1alpha1::TrinoConfigOverrides,
    GenericRoleConfig,
    JavaCommonConfig,
>;

pub type TrinoRoleGroupType =
    RoleGroup<v1alpha1::TrinoConfigFragment, JavaCommonConfig, v1alpha1::TrinoConfigOverrides>;

pub const APP_NAME: &str = "trino";
// ports
pub const HTTP_PORT: u16 = 8080;
pub const HTTPS_PORT: u16 = 8443;
pub const METRICS_PORT: u16 = 8081;
// port names
pub const HTTP_PORT_NAME: &str = "http";
pub const HTTPS_PORT_NAME: &str = "https";
pub const METRICS_PORT_NAME: &str = "metrics";
// directories
pub const CONFIG_DIR_NAME: &str = "/stackable/config";
pub const RW_CONFIG_DIR_NAME: &str = "/stackable/rwconfig";
pub const STACKABLE_SERVER_TLS_DIR: &str = "/stackable/server_tls";
pub const STACKABLE_CLIENT_TLS_DIR: &str = "/stackable/client_tls";
pub const STACKABLE_INTERNAL_TLS_DIR: &str = "/stackable/internal_tls";
pub const STACKABLE_LOG_DIR: &str = "/stackable/log";
pub const STACKABLE_MOUNT_SERVER_TLS_DIR: &str = "/stackable/mount_server_tls";
pub const STACKABLE_MOUNT_INTERNAL_TLS_DIR: &str = "/stackable/mount_internal_tls";
// store pws
pub const STACKABLE_TLS_STORE_PASSWORD: &str = "changeit";
// secret vars
pub const ENV_INTERNAL_SECRET: &str = "INTERNAL_SECRET";
pub const ENV_SPOOLING_SECRET: &str = "SPOOLING_SECRET";
// TLS
const TLS_DEFAULT_SECRET_CLASS: &str = "tls";
// Logging
pub const MAX_TRINO_LOG_FILES_SIZE: MemoryQuantity = MemoryQuantity {
    value: 10.0,
    unit: BinaryMultiple::Mebi,
};

const DEFAULT_COORDINATOR_GRACEFUL_SHUTDOWN_TIMEOUT: Duration =
    Duration::from_minutes_unchecked(15);
pub const DEFAULT_WORKER_GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_minutes_unchecked(60);

/// Convert a Kubernetes `Quantity` to a Trino property string in bytes, e.g. `"65536B"`.
pub(crate) fn quantity_to_trino_bytes(
    q: &Quantity,
) -> Result<String, stackable_operator::memory::Error> {
    let in_mebi = MemoryQuantity::try_from(q)?.scale_to(BinaryMultiple::Mebi);
    let bytes = (in_mebi.value * 1024.0 * 1024.0).round() as u64;
    Ok(format!("{bytes}B"))
}

#[derive(Snafu, Debug)]
pub enum Error {
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
}

#[versioned(
    version(name = "v1alpha1"),
    crates(
        kube_core = "stackable_operator::kube::core",
        kube_client = "stackable_operator::kube::client",
        k8s_openapi = "stackable_operator::k8s_openapi",
        schemars = "stackable_operator::schemars",
        versioned = "stackable_operator::versioned",
    ),
    skip(from)
)]
pub mod versioned {
    /// A Trino cluster stacklet. This resource is managed by the Stackable operator for Trino.
    /// Find more information on how to use it and the resources that the operator generates in the
    /// [operator documentation](DOCS_BASE_URL_PLACEHOLDER/trino/).
    #[versioned(crd(
        group = "trino.stackable.tech",
        plural = "trinoclusters",
        shortname = "trino",
        status = "TrinoClusterStatus",
        namespaced,
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
        #[serde(default)]
        pub object_overrides: ObjectOverrides,

        // no doc - it's in the struct.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub coordinators: Option<super::TrinoCoordinatorRoleType>,

        // no doc - it's in the struct.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub workers: Option<super::TrinoRoleType>,
    }

    #[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct TrinoCoordinatorRoleConfig {
        #[serde(flatten)]
        pub common: GenericRoleConfig,

        /// This field controls which [ListenerClass](DOCS_BASE_URL_PLACEHOLDER/listener-operator/listenerclass.html) is used to expose the coordinator.
        #[serde(default = "coordinator_default_listener_class")]
        pub listener_class: String,
    }

    #[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, Merge, PartialEq, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct TrinoConfigOverrides {
        // File name defined in [`crate::controller::build::properties::ConfigFileName`]
        #[serde(default, rename = "config.properties")]
        pub config_properties: KeyValueConfigOverrides,

        // File name defined in [`crate::controller::build::properties::ConfigFileName`]
        #[serde(default, rename = "node.properties")]
        pub node_properties: KeyValueConfigOverrides,

        // File name defined in [`crate::controller::build::properties::ConfigFileName`]
        #[serde(default, rename = "log.properties")]
        pub log_properties: KeyValueConfigOverrides,

        // File name defined in [`crate::controller::build::properties::ConfigFileName`]
        #[serde(default, rename = "security.properties")]
        pub security_properties: KeyValueConfigOverrides,

        // File name defined in [`crate::controller::build::properties::ConfigFileName`]
        #[serde(default, rename = "access-control.properties")]
        pub access_control_properties: KeyValueConfigOverrides,

        // File name defined in [`crate::controller::build::properties::ConfigFileName`]
        #[serde(default, rename = "exchange-manager.properties")]
        pub exchange_manager_properties: KeyValueConfigOverrides,

        // File name defined in [`crate::controller::build::properties::ConfigFileName`]
        #[serde(default, rename = "spooling-manager.properties")]
        pub spooling_manager_properties: KeyValueConfigOverrides,
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
        #[fragment_attrs(serde(default))]
        pub affinity: StackableAffinity,

        /// Time period Pods have to gracefully shut down, e.g. `30m`, `1h` or `2d`. Consult the operator documentation for details.
        #[fragment_attrs(serde(default))]
        pub graceful_shutdown_timeout: Option<Duration>,

        #[fragment_attrs(serde(default))]
        pub logging: Logging<Container>,

        /// This is the max amount of user memory a query can use across the entire cluster.
        /// See <https://trino.io/docs/current/admin/properties-resource-management.html#query-max-memory>
        pub query_max_memory: Option<String>,

        /// This is the max amount of user memory a query can use on a worker.
        /// See <https://trino.io/docs/current/admin/properties-resource-management.html#query-max-memory-per-node>
        pub query_max_memory_per_node: Option<String>,

        // We need to provide *something* that implements `Fragment`, so we pick an empty struct here.
        // Note that a unit "()" would not work, as we need something that implements `Fragment`.
        #[fragment_attrs(serde(default))]
        pub resources: Resources<TrinoStorageConfig, NoRuntimeLimits>,

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

        /// Fault tolerant execution configuration.
        /// When enabled, Trino can automatically retry queries or tasks in case of failures.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub fault_tolerant_execution:
            Option<fault_tolerant_execution::FaultTolerantExecutionConfig>,

        /// Client spooling protocol configuration.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub client_protocol: Option<client_protocol::ClientProtocolConfig>,

        /// Name of the Vector aggregator [discovery ConfigMap](DOCS_BASE_URL_PLACEHOLDER/concepts/service_discovery).
        /// It must contain the key `ADDRESS` with the address of the Vector aggregator.
        /// Follow the [logging tutorial](DOCS_BASE_URL_PLACEHOLDER/tutorials/logging-vector-aggregator)
        /// to learn how to configure log aggregation with Vector.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub vector_aggregator_config_map_name: Option<String>,
    }

    #[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub enum TrinoAuthorization {
        Opa {
            // no doc - it's in the struct.
            #[serde(default, flatten)]
            config: TrinoAuthorizationOpaConfig,
        },
    }

    #[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct TrinoAuthorizationOpaConfig {
        // no doc - it's in the struct.
        #[serde(flatten)]
        pub opa: OpaConfig,

        /// Whether to set the OPA batched column masking URI for Trino queries; defaults to true
        #[serde(default = "TrinoAuthorizationOpaConfig::enabled_column_masking_default")]
        pub enable_column_masking: bool,
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
    pub struct TrinoStorageConfig {}

    #[derive(Clone, Default, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct TrinoClusterStatus {
        #[serde(default)]
        pub conditions: Vec<ClusterCondition>,
    }
}

impl v1alpha1::TrinoAuthorizationOpaConfig {
    pub fn enabled_column_masking_default() -> bool {
        true
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
    Ord,
    PartialEq,
    PartialOrd,
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
    pub(crate) fn default_config(
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
                storage: v1alpha1::TrinoStorageConfigFragment {},
            },
            query_max_memory: None,
            query_max_memory_per_node: None,
            graceful_shutdown_timeout: Some(graceful_shutdown_timeout),
            requested_secret_lifetime: Some(requested_secret_lifetime),
        }
    }
}

impl v1alpha1::TrinoCluster {
    /// Returns a reference to the role. Raises an error if the role is not defined.
    pub fn role(&self, role_variant: &TrinoRole) -> Result<TrinoRoleType, Error> {
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
    ) -> Result<TrinoRoleGroupType, Error> {
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
    pub fn coordinator_pods(
        &self,
        namespace: &NamespaceName,
    ) -> impl Iterator<Item = TrinoPodRef> + '_ {
        let ns = namespace.to_string();
        self.spec
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
                    role_group_service_name: role_group_ref.rolegroup_headless_service_name(),
                    pod_name: format!(
                        "{role_group}-{i}",
                        role_group = role_group_ref.object_name()
                    ),
                })
            })
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

    pub fn get_opa_config(&self) -> Option<&v1alpha1::TrinoAuthorizationOpaConfig> {
        self.spec
            .cluster_config
            .authorization
            .as_ref()
            .map(|a| match a {
                v1alpha1::TrinoAuthorization::Opa { config } => config,
            })
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
}

fn extract_role_from_coordinator_config(fragment: TrinoCoordinatorRoleType) -> TrinoRoleType {
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
    use stackable_operator::versioned::test_utils::RoundtripTestData;

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
            productVersion: "479"
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
            productVersion: "479"
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
            productVersion: "479"
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
            productVersion: "479"
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
            productVersion: "479"
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
            productVersion: "479"
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
            productVersion: "479"
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
            productVersion: "479"
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
            productVersion: "479"
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
            productVersion: "479"
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

    impl RoundtripTestData for v1alpha1::TrinoClusterSpec {
        fn roundtrip_test_data() -> Vec<Self> {
            stackable_operator::utils::yaml_from_str_singleton_map(indoc::indoc! {r#"
              - image:
                  productVersion: "42"
                  pullPolicy: IfNotPresent
                clusterOperation:
                  stopped: false
                  reconciliationPaused: false
                clusterConfig:
                  catalogLabelSelector:
                    matchLabels:
                      trino: trino
                  authentication:
                    - authenticationClass: oidc
                      oidc:
                        clientCredentialsSecret: oidc-secret
                    - authenticationClass: password
                    - authenticationClass: password-other
                    - authenticationClass: ldap
                    - authenticationClass: ldap-other
                  authorization:
                    opa:
                      configMapName: opa
                      package: trino
                  tls:
                    serverSecretClass: my-tls
                    internalSecretClass: null
                  clientProtocol:
                    spooling:
                      location: s3://spooling-bucket/trino/
                      filesystem:
                        s3:
                          connection:
                            reference: minio
                  faultTolerantExecution:
                    task:
                      exchangeManager:
                        s3:
                          baseDirectories:
                            - s3://exchange-bucket/
                          connection:
                            reference: minio
                  vectorAggregatorConfigMapName: vector-aggregator-discovery
                coordinators:
                  config:
                    logging:
                      enableVectorAgent: true
                  roleConfig:
                    listenerClass: external-unstable
                  envOverrides:
                    COMMON_VAR: role-value
                    ROLE_VAR: role-value
                  roleGroups:
                    default:
                      replicas: 1
                      envOverrides:
                        COMMON_VAR: group-value
                        GROUP_VAR: group-value
                workers:
                  config:
                    resources:
                      cpu:
                        min: 300m
                        max: 600m
                      memory:
                        limit: 3Gi
                    gracefulShutdownTimeout: 5s
                    logging:
                      enableVectorAgent: true
                  envOverrides:
                    COMMON_VAR: role-value
                    ROLE_VAR: role-value
                  roleGroups:
                    default:
                      replicas: 1
                      envOverrides:
                        COMMON_VAR: group-value
                        GROUP_VAR: group-value
        "#})
            .expect("Failed to parse TrinoClusterSpec YAML")
        }
    }
}
