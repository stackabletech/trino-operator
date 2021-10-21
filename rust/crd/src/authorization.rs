use kube::api::PostParams;
use kube::core::ObjectMeta;
use kube::Api;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use stackable_operator::client;
use stackable_operator::client::Client;
use stackable_operator::error::OperatorResult;
use stackable_regorule_crd::{RegoRule, RegoRuleSpec};
use std::collections::BTreeMap;
use tracing::debug;

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
                debug!("Replacing content...");
            }

            // TODO: we spawn another client here with the correct field selector
            //    when implementing we could not make it work with the standard client.
            let rego_client = client::create_client(Some("opa.stackable.tech".to_string())).await?;
            let api: Api<RegoRule> = rego_client.get_namespaced_api("default");
            api.replace(package_name, &PostParams::default(), &old_rego_rule)
                .await?;
        }
        Err(_) => {
            debug!("No rego rule resource found. Attempting to create it...");
            // TODO: we spawn another client here with the correct field selector
            //    when implementing we could not make it work with the standard client.
            let rego_client = client::create_client(Some("opa.stackable.tech".to_string())).await?;
            let api: Api<RegoRule> = rego_client.get_namespaced_api("default");
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
    user_json.push_str(&serde_json::to_string(&user_permissions).unwrap());
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
    fn auth_test(#[case] auth: &str) {
        let _parsed_auth = parse_authorization_from_yaml(auth);
    }

    fn parse_authorization_from_yaml(authorization: &str) -> Authorization {
        let auth: Authorization = serde_yaml::from_str(authorization).unwrap();
        auth
    }
}
