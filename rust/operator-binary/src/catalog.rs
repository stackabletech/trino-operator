use std::collections::BTreeMap;

use snafu::{ResultExt, Snafu};
use stackable_operator::{
    builder::{SecretOperatorVolumeSourceBuilder, VolumeBuilder, VolumeMountBuilder},
    client::Client,
    commons::s3::S3AccessStyle,
    k8s_openapi::api::core::v1::{ConfigMapKeySelector, EnvVar, EnvVarSource, Volume, VolumeMount},
    kube::ResourceExt,
};
use stackable_trino_crd::{
    CONFIG_DIR_NAME, RW_CONFIG_DIR_NAME,
    {catalog::TrinoCatalog, S3_SECRET_DIR_NAME},
};

use self::from_trino_catalog_error::ResolveS3ConnectionDefSnafu;

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
    /// Volumes that need to be added to the pod (e.g. for S3 credentials)
    pub volumes: Vec<Volume>,
    /// Volume mounts that need to be added to the Trino container (e.g. for S3 credentials)
    pub volume_mounts: Vec<VolumeMount>,
}

impl CatalogConfig {
    fn add_property(&mut self, property: impl Into<String>, value: impl Into<String>) {
        self.properties.insert(property.into(), value.into());
    }

    fn add_env_property(&mut self, property: impl Into<String>, env: EnvVar) {
        self.add_property(property, format!("${{ENV:{}}}", env.name));
        self.env_bindings.push(env);
    }

    fn add_env_property_from_file(
        &mut self,
        property: impl Into<String>,
        file_name: impl Into<String>,
    ) {
        let property = property.into();
        let env_name = calculate_env_name(&self.name, &property);
        self.add_property(&property, format!("${{ENV:{env_name}}}"));
        self.load_env_from_files.insert(env_name, file_name.into());
    }

    fn add_configmap_property(
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
}

fn calculate_env_name(catalog: impl Into<String>, property: impl Into<String>) -> String {
    let catalog = catalog.into();
    let property = property.into().replace('.', "_").replace('-', "_");
    format!("CATALOG_{catalog}_{property}").to_uppercase()
}

impl CatalogConfig {
    pub async fn from_catalog(
        catalog: TrinoCatalog,
        client: &Client,
    ) -> Result<CatalogConfig, FromTrinoCatalogError> {
        let catalog_name = catalog.name();
        let mut config = CatalogConfig {
            name: catalog_name.to_string(),
            properties: BTreeMap::new(),
            env_bindings: Vec::new(),
            load_env_from_files: BTreeMap::new(),
            volumes: Vec::new(),
            volume_mounts: Vec::new(),
        };

        config.add_property("connector.name", catalog.spec.connector.name());

        match &catalog.spec.connector {
            stackable_trino_crd::catalog::TrinoCatalogConnector::Hive(hive) => {
                config.add_configmap_property(
                    "hive.metastore.uri",
                    hive.metastore.config_map.clone(),
                    "HIVE",
                );

                if let Some(s3_connection_def) = &hive.s3 {
                    let s3 = s3_connection_def
                        .resolve(client, catalog.namespace().as_deref())
                        .await
                        .context(ResolveS3ConnectionDefSnafu)?;
                    if let Some(endpoint) = s3.endpoint() {
                        config.add_property("hive.s3.endpoint", endpoint)
                    }
                    config.add_property("hive.s3.ssl.enabled", s3.tls.is_some().to_string());
                    if let Some(S3AccessStyle::Path) = s3.access_style {
                        config.add_property("hive.s3.path-style-access", true.to_string())
                    }
                    if let Some(credentials) = s3.credentials {
                        let secret_class = credentials.secret_class;
                        let secret_folder = format!("{S3_SECRET_DIR_NAME}/{secret_class}");
                        config.volumes.push(
                            VolumeBuilder::new(&secret_class)
                                .ephemeral(
                                    SecretOperatorVolumeSourceBuilder::new(&secret_class).build(),
                                )
                                .build(),
                        );
                        config
                            .volume_mounts
                            .push(VolumeMountBuilder::new(&secret_class, &secret_folder).build());

                        config.add_env_property_from_file(
                            "hive.s3.aws-access-key",
                            format!("{secret_folder}/accessKey"),
                        );
                        config.add_env_property_from_file(
                            "hive.s3.aws-secret-key",
                            format!("{secret_folder}/secretKey"),
                        );
                    }

                    // TODO: Handle TLS settings (related to https://github.com/stackabletech/trino-operator/pull/244)
                }

                if let Some(hdfs) = &hive.hdfs {
                    config.add_property(
                        "hive.config.resources",
                        format!("{RW_CONFIG_DIR_NAME}/catalog/{catalog_name}/hdfs-config/hdfs-site.xml"),
                    );

                    let volume_name = format!("{catalog_name}-hdfs");
                    config.volumes.push(
                        VolumeBuilder::new(&volume_name)
                            .with_config_map(&hdfs.config_map)
                            .build(),
                    );
                    config
                        .volume_mounts
                        .push(VolumeMountBuilder::new(&volume_name, format!("{CONFIG_DIR_NAME}/catalog/{catalog_name}/hdfs-config")).build());
                }
            }
        }

        config.properties.extend(catalog.spec.config_overrides);
        Ok(config)
    }
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum FromTrinoCatalogError {
    #[snafu(display("failed to resolve S3ConnectionDef"))]
    ResolveS3ConnectionDef {
        source: stackable_operator::error::Error,
    },
}
