use crate::TrinoRole;
use duplicate::duplicate;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
use k8s_openapi::chrono::Utc;
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;
use serde_json::Value;
use stackable_operator::command::{CanBeRolling, HasRoles};
use stackable_operator::command_controller::Command;

#[derive(Clone, CustomResource, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[kube(
    group = "command.trino.stackable.tech",
    version = "v1alpha1",
    kind = "Restart",
    plural = "restarts",
    namespaced
)]
#[kube(status = "CommandStatus")]
#[serde(rename_all = "camelCase")]
pub struct RestartCommandSpec {
    pub name: String,
    pub rolling: bool,
    pub roles: Option<Vec<TrinoRole>>,
}

#[derive(Clone, CustomResource, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[kube(
    group = "command.trino.stackable.tech",
    version = "v1alpha1",
    kind = "Start",
    plural = "starts",
    namespaced
)]
#[kube(status = "CommandStatus")]
#[serde(rename_all = "camelCase")]
pub struct StartCommandSpec {
    pub name: String,
    pub rolling: bool,
    pub roles: Option<Vec<TrinoRole>>,
}

#[derive(Clone, CustomResource, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[kube(
    group = "command.trino.stackable.tech",
    version = "v1alpha1",
    kind = "Stop",
    plural = "stops",
    namespaced
)]
#[kube(status = "CommandStatus")]
#[serde(rename_all = "camelCase")]
pub struct StopCommandSpec {
    pub name: String,
    pub rolling: bool,
    pub roles: Option<Vec<TrinoRole>>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CommandStatus {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<Time>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<Time>,
}

#[duplicate(Name; [Restart]; [Start]; [Stop])]
impl Command for Name {
    fn owner_name(&self) -> String {
        self.spec.name.clone()
    }

    fn start_patch(&mut self) -> Value {
        let time = Time(Utc::now());
        match &mut self.status {
            Some(status) => {
                status.started_at = Some(time.clone());
            }
            None => {
                self.status = Some(CommandStatus {
                    started_at: Some(time.clone()),
                    finished_at: None,
                })
            }
        }
        json!({ "startedAt": time })
    }

    fn start_time(&self) -> Option<&Time> {
        self.status
            .as_ref()
            .and_then(|status| status.started_at.as_ref())
    }

    fn finish_patch(&mut self) -> Value {
        let time = Time(Utc::now());
        match &mut self.status {
            Some(status) => {
                status.finished_at = Some(time.clone());
            }
            None => {
                self.status = Some(CommandStatus {
                    started_at: None,
                    finished_at: Some(time.clone()),
                })
            }
        }
        json!({ "finishedAt": time })
    }

    fn finish_time(&self) -> Option<&Time> {
        self.status
            .as_ref()
            .and_then(|status| status.finished_at.as_ref())
    }
}

#[duplicate(Name; [Restart]; [Start]; [Stop])]
impl CanBeRolling for Name {
    fn is_rolling(&self) -> bool {
        self.spec.rolling
    }
}

#[duplicate(Name; [Restart]; [Start]; [Stop])]
impl HasRoles for Name {
    fn get_role_order(&self) -> Option<Vec<String>> {
        self.spec
            .roles
            .clone()
            .map(|roles| roles.into_iter().map(|role| role.to_string()).collect())
    }
}
