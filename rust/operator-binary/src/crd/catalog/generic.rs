use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use stackable_operator::{
    k8s_openapi::api::core::v1::{ConfigMapKeySelector, SecretKeySelector},
    schemars::{self, JsonSchema},
};

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GenericConnector {
    /// Name of the Trino connector.
    /// Will be passed to `connector.name`.
    pub connector_name: String,
    /// A map of properties to put in the connector configuration file.
    /// They can be specified either as a raw value or be read from a Secret or ConfigMap.
    #[serde(default)]
    pub properties: BTreeMap<String, Property>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Property {
    // Raw value to be put into the config.
    Value(String),
    // Read property value from a Secret by specifying a `SecretKeySelector`.
    ValueFromSecret {
        #[serde(flatten)]
        secret_key_selector: SecretKeySelector,
    },
    // Read property value from a ConfigMap by specifying a `ConfigMapKeySelector`.
    ValueFromConfigMap {
        #[serde(flatten)]
        config_map_key_selector: ConfigMapKeySelector,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::catalog::{TrinoCatalogConnector, v1alpha1};

    #[test]
    fn test_cr_parsing() {
        let input = r#"
        apiVersion: trino.stackable.tech/v1alpha1
        kind: TrinoCatalog
        metadata:
          name: postgres
          labels:
            trino: simple-trino
        spec:
          connector:
            generic:
              connectorName: postgresql
              properties:
                connection-url:
                  value: jdbc:postgresql://example.net:5432/database
                connection-user:
                  valueFromSecret:
                    name: my-postgresql-credentials-secret
                    key: user
                connection-password:
                  valueFromSecret:
                    name: my-postgresql-credentials-secret
                    key: password
        "#;
        let deserializer = serde_yaml::Deserializer::from_str(input);
        let catalog: v1alpha1::TrinoCatalog =
            serde_yaml::with::singleton_map_recursive::deserialize(deserializer).unwrap();

        assert_eq!(
            catalog.spec.connector,
            TrinoCatalogConnector::Generic(GenericConnector {
                connector_name: "postgresql".to_string(),
                properties: BTreeMap::from([
                    (
                        "connection-url".to_string(),
                        Property::Value("jdbc:postgresql://example.net:5432/database".to_string())
                    ),
                    ("connection-user".to_string(), Property::ValueFromSecret {
                        secret_key_selector: SecretKeySelector {
                            key: "user".to_string(),
                            name: "my-postgresql-credentials-secret".to_string(),
                            optional: None,
                        }
                    }),
                    (
                        "connection-password".to_string(),
                        Property::ValueFromSecret {
                            secret_key_selector: SecretKeySelector {
                                key: "password".to_string(),
                                name: "my-postgresql-credentials-secret".to_string(),
                                optional: None,
                            }
                        }
                    ),
                ]),
            })
        );
    }
}
