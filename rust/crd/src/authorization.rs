use crate::{TrinoCluster, TrinoClusterSpec};

use serde::{Deserialize, Serialize};
use snafu::{ResultExt, Snafu};
use stackable_operator::builder::{ConfigMapBuilder, ObjectMetaBuilder};
use stackable_operator::client::Client;
use stackable_operator::k8s_openapi::api::core::v1::ConfigMap;
use stackable_operator::kube::ResourceExt;
use stackable_operator::schemars::{self, JsonSchema};
use std::collections::BTreeMap;

const FIELD_MANAGER_SCOPE: &str = "trinocluster";

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("failed to build rego rule config map"))]
    FailedRegoRuleConfigMapBuild {
        source: stackable_operator::error::Error,
    },
    #[snafu(display("failed to apply rego rule config map"))]
    FailedRegoRuleConfigMapApply {
        source: stackable_operator::error::Error,
    },
    #[snafu(display("object is missing metadata to build owner reference"))]
    ObjectMissingMetadataForOwnerRef {
        source: stackable_operator::error::Error,
    },
    #[snafu(display("failed to convert permission set to JSON: {permissions:?}"))]
    JsonConversion {
        source: serde_json::Error,
        permissions: BTreeMap<String, UserPermission>,
    },
}

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Authorization {
    pub package: String,
    pub permissions: BTreeMap<String, UserPermission>,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserPermission {
    pub schemas: Option<AccessPermission>,
    pub tables: Option<BTreeMap<String, AccessPermission>>,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessPermission {
    pub read: Option<bool>,
    pub write: Option<bool>,
}

pub async fn create_rego_rules(client: &Client, trino: &TrinoCluster) -> Result<()> {
    let spec: &TrinoClusterSpec = &trino.spec;

    if let Some(authorization) = &spec.authorization {
        let rego_rules = build_rego_rules(authorization)?;
        create_or_update_rego_config_map(client, trino, &authorization.package, rego_rules).await?;
    }

    Ok(())
}

async fn create_or_update_rego_config_map(
    client: &Client,
    trino: &TrinoCluster,
    package_name: &str,
    rego_rules: String,
) -> Result<ConfigMap> {
    let config_map_data = [(format!("{}.rego", package_name), rego_rules)]
        .into_iter()
        .collect::<BTreeMap<_, _>>();

    let config_map = ConfigMapBuilder::new()
        .metadata(
            ObjectMetaBuilder::new()
                .name_and_namespace(trino)
                .name(format!("{}-opa-rego-{}", trino.name(), package_name))
                .labels(
                    [(
                        "opa.stackable.tech/bundle".to_string(),
                        package_name.to_string(),
                    )]
                    .into_iter()
                    .collect::<BTreeMap<_, _>>(),
                )
                .ownerreference_from_resource(trino, None, Some(true))
                .context(ObjectMissingMetadataForOwnerRefSnafu)?
                .build(),
        )
        .data(config_map_data)
        .build()
        .context(FailedRegoRuleConfigMapBuildSnafu)?;

    client
        .apply_patch(FIELD_MANAGER_SCOPE, &config_map, &config_map)
        .await
        .context(FailedRegoRuleConfigMapApplySnafu)
}

fn build_rego_rules(authorization_rules: &Authorization) -> Result<String> {
    let mut rules = String::new();

    rules.push_str(&format!("    package {}\n\n", authorization_rules.package));
    rules.push_str(&build_user_permission_json(
        &authorization_rules.permissions,
    )?);
    rules.push_str(&build_main_rego_rules());
    rules.push_str(&build_helper_rego_rules());

    Ok(rules)
}

fn build_user_permission_json(
    user_permissions: &BTreeMap<String, UserPermission>,
) -> Result<String> {
    let mut user_json = String::new();

    let json = &serde_json::to_string(&user_permissions).with_context(|_| JsonConversionSnafu {
        permissions: user_permissions.clone(),
    })?;

    user_json.push_str("    users = ");
    user_json.push_str(json);
    user_json.push('\n');

    Ok(user_json)
}

fn build_main_rego_rules() -> String {
    let main_rules = "
    default can_access_table = false
    can_access_table {
        user_can_read_table
    }
    
    default can_create_table = false
    can_create_table {
        user_can_write_table
    }
    
    default can_drop_table = false
    can_drop_table {
        user_can_write_table
    }
    
    default can_show_tables = false
    can_show_tables {
        user_can_read_table
    }
    
    default can_access_schema = false
    can_access_schema {
        user_can_read_schema
    }
    
    default can_create_schema = false
    can_create_schema {
        user_can_write_schema
    }
    
    default can_drop_schema = false
    can_drop_schema {
        user_can_write_schema
    }
    
    default can_show_schemas = false
    can_show_schemas {
        user_can_read_schema
    }
    
    default can_access_catalog = false
    can_access_catalog {
        is_valid_user
    }
    
    default can_execute_query = false
    can_execute_query {
        is_valid_user
    }
    
    default can_select_from_columns = false
    can_select_from_columns {
        is_valid_user
        can_access_table
    }
    
    default can_view_query_owned_by = false
    can_view_query_owned_by {
        is_valid_user
    }
";

    main_rules.to_string()
}

fn build_helper_rego_rules() -> String {
    let sub_rules = "
    user_can_read_table {
        users[input.user.name].tables[input.request.table.table].read == true
    }
    
    user_can_write_table {
        users[input.user.name].tables[input.request.table.table].write == true
    }
    
    user_can_read_schema {
        users[input.user.name].schemas.read == true
    }
    
    user_can_write_schema {
        users[input.user.name].schemas.write == true
    }
    
    is_valid_user {
        _ = users[input.user.name]
    }
";

    sub_rules.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use indoc::indoc;
    use rstest::rstest;

    #[rstest]
    #[case::test(
    indoc! {"
        package: trino
        permissions:
          admin:
            schemas:
              read: true
              write: true
            tables:
              test_table_1:
                read: true
                write: true
              test_table_2:
                read: true
          bob:
            schemas:
              read: false
              write: false
            tables:
              test_table_1:
                read: true
    "},
    )]
    fn test_build_rego_rules(#[case] auth: &str) -> Result<()> {
        let authorization = parse_authorization_from_yaml(auth);
        let rego_rules = build_rego_rules(&authorization)?;

        assert!(rego_rules.contains("package trino"));
        assert!(rego_rules.contains("user_can_read_table"));
        assert!(rego_rules.contains("can_drop_schema"));

        Ok(())
    }

    fn parse_authorization_from_yaml(authorization: &str) -> Authorization {
        let auth: Authorization = serde_yaml::from_str(authorization).unwrap();
        auth
    }
}
