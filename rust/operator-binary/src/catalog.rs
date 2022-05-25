use std::collections::HashMap;

use snafu::{OptionExt, Snafu};
use stackable_operator::k8s_openapi::api::core::v1::{ConfigMapKeySelector, EnvVar, EnvVarSource};
use stackable_trino_crd::catalog::TrinoCatalog;

pub struct CatalogConfig {
    pub name: String,
    pub properties: HashMap<String, String>,
    pub env_bindings: Vec<EnvVar>,
}

impl CatalogConfig {
    fn add_property(&mut self, property: impl Into<String>, value: impl Into<String>) {
        self.properties.insert(property.into(), value.into());
    }

    fn add_env_property(&mut self, property: impl Into<String>, env: EnvVar) {
        self.add_property(property, format!("${{ENV:{}}}", env.name));
        self.env_bindings.push(env);
    }

    fn add_configmap_property(
        &mut self,
        property: impl Into<String>,
        config_map: impl Into<String>,
        cm_key: impl Into<String>,
    ) {
        let property = property.into();
        let env_name = format!(
            "CATALOG_{cat_name}_{property}",
            cat_name = self.name,
            property = property.replace('.', "-")
        );
        self.add_env_property(
            property,
            EnvVar {
                name: env_name,
                value: None,
                value_from: Some(EnvVarSource {
                    config_map_key_ref: Some(ConfigMapKeySelector {
                        name: Some(config_map.into()),
                        key: cm_key.into(),
                        ..ConfigMapKeySelector::default()
                    }),
                    ..EnvVarSource::default()
                }),
            },
        );
    }
}

impl TryFrom<TrinoCatalog> for CatalogConfig {
    type Error = FromTrinoCatalogError;

    fn try_from(catalog: TrinoCatalog) -> Result<CatalogConfig, FromTrinoCatalogError> {
        let mut config = CatalogConfig {
            name: catalog
                .metadata
                .name
                .context(from_trino_catalog_error::NoCatalogNameSnafu)?,
            properties: HashMap::new(),
            env_bindings: Vec::new(),
        };

        match catalog
            .spec
            .connector
            .as_ref()
            .context(from_trino_catalog_error::NoConnectorSnafu)?
        {
            stackable_trino_crd::catalog::TrinoCatalogConnector::Hive(hive) => {
                config.add_property("connector.name", "hive");
                config.add_configmap_property(
                    "hive.metastore.uri",
                    hive.metastore_config_map
                        .as_deref()
                        .context(from_trino_catalog_error::HiveNoMetastoreSnafu)?,
                    "HIVE",
                )
            }
        }

        config.properties.extend(catalog.spec.config_overrides);
        Ok(config)
    }
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum FromTrinoCatalogError {
    #[snafu(display("catalog has no name"))]
    NoCatalogName,
    #[snafu(display("catalog doesn't define any defines connector"))]
    NoConnector,
    #[snafu(display("hive catalog defines no metastore config map"))]
    HiveNoMetastore,
}
