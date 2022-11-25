use stackable_operator::{
    client::Client,
    k8s_openapi::api::core::v1::{ConfigMapKeySelector, EnvVar, EnvVarSource, Volume, VolumeMount},
    kube::{Resource, ResourceExt},
};
use stackable_trino_crd::catalog::{TrinoCatalog, TrinoCatalogConnector};
use std::collections::BTreeMap;

use super::{FromTrinoCatalogError, ToCatalogConfig};

pub struct CatalogConfig {
    /// Name of the catalog
    pub name: String,
    /// Properties of the catalog
    pub properties: BTreeMap<String, String>,
    /// List of EnvVar that will be added to every Trino container
    pub env_bindings: Vec<EnvVar>,
    /// Env-Vars that should be exported.
    /// The value will be read from the file specified.
    /// You can think of it like `export <key>=$(cat <value>)`
    pub load_env_from_files: BTreeMap<String, String>,
    /// Additional commands that needs to be executed before starting Trino
    pub init_container_extra_start_commands: Vec<String>,
    /// Volumes that need to be added to the pod (e.g. for S3 credentials)
    pub volumes: Vec<Volume>,
    /// Volume mounts that need to be added to the Trino container (e.g. for S3 credentials)
    pub volume_mounts: Vec<VolumeMount>,
}

impl CatalogConfig {
    pub fn new(name: impl Into<String>, connector_name: impl Into<String>) -> Self {
        let mut config = CatalogConfig {
            name: name.into(),
            properties: BTreeMap::new(),
            env_bindings: Vec::new(),
            load_env_from_files: BTreeMap::new(),
            init_container_extra_start_commands: Vec::new(),
            volumes: Vec::new(),
            volume_mounts: Vec::new(),
        };
        config.add_property("connector.name", connector_name);
        config
    }

    pub fn add_property(&mut self, property: impl Into<String>, value: impl Into<String>) {
        self.properties.insert(property.into(), value.into());
    }

    pub fn add_env_property(&mut self, property: impl Into<String>, env: EnvVar) {
        self.add_property(property, format!("${{ENV:{}}}", env.name));
        self.env_bindings.push(env);
    }

    pub fn add_env_property_from_file(
        &mut self,
        property: impl Into<String>,
        file_name: impl Into<String>,
    ) {
        let property = property.into();
        let env_name = calculate_env_name(&self.name, &property);
        self.add_property(&property, format!("${{ENV:{env_name}}}"));
        self.load_env_from_files.insert(env_name, file_name.into());
    }

    pub fn add_configmap_property(
        &mut self,
        property: impl Into<String>,
        config_map: impl Into<String>,
        config_map_key: impl Into<String>,
    ) {
        let property = property.into();
        let env_name = calculate_env_name(&self.name, &property);
        self.add_env_property(
            &property,
            EnvVar {
                name: env_name,
                value: None,
                value_from: Some(EnvVarSource {
                    config_map_key_ref: Some(ConfigMapKeySelector {
                        name: Some(config_map.into()),
                        key: config_map_key.into(),
                        ..ConfigMapKeySelector::default()
                    }),
                    ..EnvVarSource::default()
                }),
            },
        );
    }

    pub async fn from_catalog(
        catalog: TrinoCatalog,
        client: &Client,
    ) -> Result<CatalogConfig, FromTrinoCatalogError> {
        let catalog_name = catalog
            .meta()
            .name
            .clone()
            .ok_or(FromTrinoCatalogError::InvalidCatalogSpec)?;
        let catalog_namespace = catalog.namespace();

        let mut catalog_config = match catalog.spec.connector {
            TrinoCatalogConnector::BlackHole(connector) => {
                connector
                    .to_catalog_config(&catalog_name, catalog_namespace, client)
                    .await
            }
            TrinoCatalogConnector::GoogleSheet(connector) => {
                connector
                    .to_catalog_config(&catalog_name, catalog_namespace, client)
                    .await
            }
            TrinoCatalogConnector::Hive(connector) => {
                connector
                    .to_catalog_config(&catalog_name, catalog_namespace, client)
                    .await
            }
            TrinoCatalogConnector::Iceberg(connector) => {
                connector
                    .to_catalog_config(&catalog_name, catalog_namespace, client)
                    .await
            }
            TrinoCatalogConnector::Tpcds(connector) => {
                connector
                    .to_catalog_config(&catalog_name, catalog_namespace, client)
                    .await
            }
            TrinoCatalogConnector::Tpch(connector) => {
                connector
                    .to_catalog_config(&catalog_name, catalog_namespace, client)
                    .await
            }
        }?;

        catalog_config
            .properties
            .extend(catalog.spec.config_overrides);

        Ok(catalog_config)
    }
}

fn calculate_env_name(catalog: impl Into<String>, property: impl Into<String>) -> String {
    let catalog = catalog.into().replace(['.', '-'], "_");
    let property = property.into().replace(['.', '-'], "_");
    format!("CATALOG_{catalog}_{property}").to_uppercase()
}
