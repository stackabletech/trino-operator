use crate::{TrinoCluster, TrinoClusterSpec, FIELD_MANAGER_SCOPE};

use serde::{Deserialize, Serialize};
use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::client::Client;
use stackable_operator::kube::core::ObjectMeta;
use stackable_operator::kube::runtime::reflector::ObjectRef;
use stackable_operator::kube::ResourceExt;
use stackable_operator::schemars::{self, JsonSchema};
use stackable_regorule_crd::{RegoRule, RegoRuleSpec};
use std::collections::BTreeMap;
use tracing::debug;

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("object has no namespace associated {trino}"))]
    NoNamespace { trino: ObjectRef<TrinoCluster> },
    #[snafu(display("failed to update rego rule {rego}"))]
    FailedRegoRuleUpdate {
        source: stackable_operator::error::Error,
        rego: ObjectRef<RegoRule>,
    },
    #[snafu(display("failed to create rego rule {rego}"))]
    FailedRegoRuleCreate {
        source: stackable_operator::error::Error,
        rego: ObjectRef<RegoRule>,
    },
    #[snafu(display("no `metadata.name` found for rego rule {rego}"))]
    MissingRegoRuleName { rego: ObjectRef<RegoRule> },
    #[snafu(display("failed to convert permission set to JSON: {permissions:?}"))]
    FailedJsonConversion {
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
        create_or_update_rego_rule_resource(client, trino, &authorization.package, rego_rules)
            .await?;
    }

    Ok(())
}

async fn create_or_update_rego_rule_resource(
    client: &Client,
    trino: &TrinoCluster,
    package_name: &str,
    rego_rules: String,
) -> Result<RegoRule> {
    let new_rego_rule_spec = RegoRuleSpec { rego: rego_rules };
    let namespace = trino.namespace();

    let rego_rule_resource = RegoRule {
        metadata: ObjectMeta {
            name: Some(package_name.to_string()),
            namespace: namespace.clone(),
            ..Default::default()
        },
        spec: new_rego_rule_spec.clone(),
    };

    match client
        .get::<RegoRule>(package_name, namespace.as_deref())
        .await
    {
        Ok(old_rego_rule) => {
            debug!("Found existing rego rule: {:?}", old_rego_rule);

            if old_rego_rule.spec.rego != new_rego_rule_spec.rego {
                debug!(
                    "Existing Rego Rule [{}] differs from spec. Replacing content...",
                    old_rego_rule.metadata.name.as_deref().with_context(|| {
                        MissingRegoRuleNameSnafu {
                            rego: ObjectRef::from_obj(&old_rego_rule),
                        }
                    })?
                );

                client
                    .apply_patch(
                        FIELD_MANAGER_SCOPE,
                        &rego_rule_resource,
                        &rego_rule_resource,
                    )
                    .await
                    .with_context(|_| FailedRegoRuleUpdateSnafu {
                        rego: ObjectRef::from_obj(&rego_rule_resource),
                    })?;
            }
        }
        Err(_) => {
            debug!("No rego rule resource found. Attempting to create it...");

            client
                .apply_patch(
                    FIELD_MANAGER_SCOPE,
                    &rego_rule_resource,
                    &rego_rule_resource,
                )
                .await
                .with_context(|_| FailedRegoRuleCreateSnafu {
                    rego: ObjectRef::from_obj(&rego_rule_resource),
                })?;
        }
    }

    Ok(rego_rule_resource)
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

    let json =
        &serde_json::to_string(&user_permissions).with_context(|_| FailedJsonConversionSnafu {
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
