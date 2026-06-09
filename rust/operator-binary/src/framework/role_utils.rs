//! Vendored variant of `stackable_operator::v2::role_utils` from the
//! `smooth-operator` branch, with simplifications appropriate for trino-operator.
//!
//! Differences from upstream:
//! - No `cli_overrides_to_vec` helper, `ResourceNames`, or service-account helpers.
//! - The `CommonConfig` (a.k.a. `product_specific_common_config`) does NOT need to
//!   implement `Merge`. Upstream Trino uses `JavaCommonConfig`, which intentionally
//!   does not implement `Merge` because its inner `JvmArgumentOverrides::try_merge`
//!   is fallible (regex validation). Merging JVM argument overrides for Trino is
//!   handled separately via `Role::get_merged_jvm_argument_overrides`. The
//!   `RoleGroupConfig::product_specific_common_config` field here simply carries
//!   the role-group level value through.
//!
//! Replace with `stackable_operator::v2::role_utils::*` once upstream publishes
//! the module.

use std::{
    collections::{BTreeMap, HashMap},
    str::FromStr,
};

use serde::Serialize;
use snafu::{ResultExt, Snafu};
use stackable_operator::{
    config::{
        fragment::{self, FromFragment},
        merge::{Merge, merge},
    },
    k8s_openapi::{DeepMerge, api::core::v1::PodTemplateSpec},
    role_utils::{Role, RoleGroup},
    schemars::JsonSchema,
    v2::builder::pod::container::{self, EnvVarName, EnvVarSet},
};

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("failed to validate the role group config"))]
    ValidateConfig { source: fragment::ValidationError },

    #[snafu(display("invalid environment variable override name"))]
    ParseEnvVarName { source: container::Error },
}

/// Trino-friendly view of a validated, merged `RoleGroup`.
///
/// Mirrors `stackable_operator::v2::role_utils::RoleGroupConfig` on the
/// `smooth-operator` branch.
#[derive(Clone, Debug, PartialEq)]
pub struct RoleGroupConfig<Config, CommonConfig, ConfigOverrides> {
    pub replicas: u16,
    pub config: Config,
    pub config_overrides: ConfigOverrides,
    pub env_overrides: EnvVarSet,
    pub cli_overrides: BTreeMap<String, String>,
    pub pod_overrides: PodTemplateSpec,
    pub product_specific_common_config: CommonConfig,
}

/// Merges and validates the `RoleGroup` with the given `role` and `default_config`,
/// returning a `RoleGroupConfig`.
///
/// Merge order matches `with_validated_config` on `smooth-operator`:
/// - `Config` (Fragment): `default_config <- role.config <- rg.config` via `Merge::merge`,
///   then validated to `ValidatedConfig` via `FromFragment`.
/// - `ConfigOverrides`: `role.config_overrides <- rg.config_overrides` via `Merge::merge`.
/// - `env_overrides` / `cli_overrides`: `extend` (rg keys overwrite role keys).
/// - `pod_overrides`: `DeepMerge::merge_from` (rg overrides role).
/// - `product_specific_common_config`: passes through the role-group level value
///   (see module docs for rationale).
pub fn with_validated_config<ValidatedConfig, CommonConfig, Config, RoleConfig, ConfigOverrides>(
    role_group: &RoleGroup<Config, CommonConfig, ConfigOverrides>,
    role: &Role<Config, ConfigOverrides, RoleConfig, CommonConfig>,
    default_config: &Config,
) -> Result<RoleGroupConfig<ValidatedConfig, CommonConfig, ConfigOverrides>, Error>
where
    ValidatedConfig: FromFragment<Fragment = Config>,
    CommonConfig: Clone + Default + JsonSchema + Serialize,
    Config: Clone + Merge,
    RoleConfig: Default + JsonSchema + Serialize,
    ConfigOverrides: Clone + Default + JsonSchema + Merge + Serialize,
{
    let validated_config =
        validate_config(role_group, role, default_config).context(ValidateConfigSnafu)?;
    Ok(RoleGroupConfig {
        replicas: role_group.replicas.unwrap_or(1),
        config: validated_config,
        config_overrides: merged_config_overrides(
            &role.config.config_overrides,
            role_group.config.config_overrides.clone(),
        ),
        env_overrides: merged_env_overrides(
            &role.config.env_overrides,
            &role_group.config.env_overrides,
        )?,
        cli_overrides: merged_cli_overrides(
            role.config.cli_overrides.clone(),
            role_group.config.cli_overrides.clone(),
        ),
        pod_overrides: merged_pod_overrides(
            role.config.pod_overrides.clone(),
            role_group.config.pod_overrides.clone(),
        ),
        product_specific_common_config: role_group.config.product_specific_common_config.clone(),
    })
}

fn validate_config<ValidatedConfig, CommonConfig, Config, RoleConfig, ConfigOverrides>(
    role_group: &RoleGroup<Config, CommonConfig, ConfigOverrides>,
    role: &Role<Config, ConfigOverrides, RoleConfig, CommonConfig>,
    default_config: &Config,
) -> Result<ValidatedConfig, fragment::ValidationError>
where
    ValidatedConfig: FromFragment<Fragment = Config>,
    CommonConfig: Default + JsonSchema + Serialize,
    Config: Clone + Merge,
    RoleConfig: Default + JsonSchema + Serialize,
    ConfigOverrides: Default + JsonSchema + Serialize,
{
    role_group.validate_config(role, default_config)
}

fn merged_config_overrides<ConfigOverrides>(
    role_config_overrides: &ConfigOverrides,
    role_group_config_overrides: ConfigOverrides,
) -> ConfigOverrides
where
    ConfigOverrides: Merge,
{
    merge(role_group_config_overrides, role_config_overrides)
}

fn merged_env_overrides(
    role_env_overrides: &HashMap<String, String>,
    role_group_env_overrides: &HashMap<String, String>,
) -> Result<EnvVarSet, Error> {
    // Process the role first, then the role group, so that role-group overrides win on key
    // collisions (`EnvVarSet::with_value` overrides earlier entries with the same name).
    let mut env_overrides = EnvVarSet::new();
    for (name, value) in role_env_overrides
        .iter()
        .chain(role_group_env_overrides.iter())
    {
        env_overrides = env_overrides.with_value(
            &EnvVarName::from_str(name).context(ParseEnvVarNameSnafu)?,
            value.clone(),
        );
    }
    Ok(env_overrides)
}

fn merged_cli_overrides(
    role_cli_overrides: BTreeMap<String, String>,
    role_group_cli_overrides: BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let mut merged = role_cli_overrides;
    merged.extend(role_group_cli_overrides);
    merged
}

fn merged_pod_overrides(
    role_pod_overrides: PodTemplateSpec,
    role_group_pod_overrides: PodTemplateSpec,
) -> PodTemplateSpec {
    let mut merged = role_pod_overrides;
    merged.merge_from(role_group_pod_overrides);
    merged
}
