use serde::{Deserialize, Serialize};
use stackable_operator::client;
use stackable_operator::client::Client;
use stackable_operator::error::OperatorResult;
use stackable_operator::kube::api::PostParams;
use stackable_operator::kube::core::ObjectMeta;
use stackable_operator::kube::Api;
use stackable_operator::schemars::{self, JsonSchema};
use stackable_regorule_crd::{RegoRule, RegoRuleSpec};
use std::collections::BTreeMap;
use tracing::{debug, warn};

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
pub struct AccessPermission {
    pub read: Option<bool>,
    pub write: Option<bool>,
}

pub async fn create_or_update_rego_rule_resource(
    client: &Client,
    package_name: &str,
    rego_rules: String,
) -> OperatorResult<RegoRule> {
    let new_rego_rule_spec = RegoRuleSpec { rego: rego_rules };

    let rego_rule_resource = RegoRule {
        api_version: "opa.stackable.tech/v1alpha1".to_string(),
        kind: "RegoRule".to_string(),
        metadata: ObjectMeta {
            name: Some(package_name.to_string()),
            ..Default::default()
        },
        spec: new_rego_rule_spec.clone(),
    };

    match client.get::<RegoRule>(package_name, Some("default")).await {
        Ok(mut old_rego_rule) => {
            debug!("Found existing rego rule: {:?}", old_rego_rule);

            if old_rego_rule.spec.rego != new_rego_rule_spec.rego {
                old_rego_rule.spec.rego = new_rego_rule_spec.rego;
                debug!(
                    "Existing Rego Rule [{}] differs from spec. Replacing content...",
                    old_rego_rule
                        .metadata
                        .name
                        .as_deref()
                        .unwrap_or("<no-name-set>")
                );

                let api = get_api("opa.stackable.tech", "default").await?;
                api.replace(package_name, &PostParams::default(), &old_rego_rule)
                    .await?;
            }
        }
        Err(_) => {
            debug!("No rego rule resource found. Attempting to create it...");
            let api = get_api("opa.stackable.tech", "default").await?;
            api.create(&PostParams::default(), &rego_rule_resource)
                .await?;
        }
    }

    Ok(rego_rule_resource)
}

pub fn build_rego_rules(authorization_rules: &Authorization) -> String {
    let mut rules = String::new();

    rules.push_str(&format!("    package {}\n\n", authorization_rules.package));
    rules.push_str(&build_user_permission_json(
        &authorization_rules.permissions,
    ));
    rules.push_str(&build_main_rego_rules());
    rules.push_str(&build_helper_rego_rules());

    rules
}

fn build_user_permission_json(user_permissions: &BTreeMap<String, UserPermission>) -> String {
    let mut user_json = String::new();

    user_json.push_str("    users = ");
    match &serde_json::to_string(&user_permissions) {
        Ok(json) => user_json.push_str(json),
        Err(err) => warn!(
            "Could not convert user permissions to json. Please check the input: {}",
            err.to_string()
        ),
    }
    user_json.push('\n');

    user_json
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

async fn get_api(field_manager: &str, namespace: &str) -> OperatorResult<Api<RegoRule>> {
    // TODO: We spawn another client here with the correct field selector.
    //    During implementation we could not make it work with the standard client.
    //    We needed a different field selector (opa.stackable.tech) instead of the trino one.
    let rego_client = client::create_client(Some(field_manager.to_string())).await?;
    Ok(rego_client.get_namespaced_api(namespace))
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
    fn test_build_rego_rules(#[case] auth: &str) {
        let authorization = parse_authorization_from_yaml(auth);
        let rego_rules = build_rego_rules(&authorization);

        assert!(rego_rules.contains("package trino"));
        assert!(rego_rules.contains("user_can_read_table"));
        assert!(rego_rules.contains("can_drop_schema"));
    }

    fn parse_authorization_from_yaml(authorization: &str) -> Authorization {
        let auth: Authorization = serde_yaml::from_str(authorization).unwrap();
        auth
    }
}
