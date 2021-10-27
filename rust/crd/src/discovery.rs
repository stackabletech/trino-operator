use crate::discovery::TicketReferences::ErrTrinoPodWithoutName;
use crate::error::Error::{ObjectWithoutName, PodWithoutHostname};
use crate::error::TrinoOperatorResult;
use crate::{TrinoRole, APP_NAME, HTTP_PORT};
use k8s_openapi::api::core::v1::Pod;
use stackable_operator::labels::APP_COMPONENT_LABEL;
use strum_macros::Display;
use tracing::{debug, warn};

#[derive(Display)]
pub enum TicketReferences {
    ErrTrinoPodWithoutName,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct TrinoDiscovery {
    pub node_name: String,
    pub http_port: String,
    pub protocol: TrinoDiscoveryProtocol,
}

impl TrinoDiscovery {
    pub fn connection_string(&self) -> String {
        let protocol = match self.protocol {
            TrinoDiscoveryProtocol::Http => "http",
            TrinoDiscoveryProtocol::Https => "https",
        };

        format!("{}://{}:{}", protocol, self.node_name, self.http_port)
    }
}

#[derive(Clone, Debug, Display, Eq, Hash, PartialEq)]
pub enum TrinoDiscoveryProtocol {
    #[strum(serialize = "http")]
    Http,
    #[strum(serialize = "https")]
    Https,
}

impl Default for TrinoDiscoveryProtocol {
    fn default() -> Self {
        Self::Http
    }
}

/// Builds the actual connection string after all necessary information has been retrieved.
/// Takes a list of pods belonging to this cluster from which the hostnames are retrieved.
/// Checks the 'http' container port to retrieve the correct specified port.
///
/// WARNING: For now this only works with one coordinator.
///
/// # Arguments
///
/// * `trino_pods` - All pods belonging to the cluster
///
pub fn get_trino_discovery_from_pods(
    trino_pods: &[Pod],
) -> TrinoOperatorResult<Option<TrinoDiscovery>> {
    let name_node_str = &TrinoRole::Coordinator.to_string();

    // filter for coordinators nodes
    let filtered_pods: Vec<&Pod> = trino_pods
        .iter()
        .filter(|pod| {
            pod.metadata
                .labels
                .as_ref()
                .and_then(|labels| labels.get(APP_COMPONENT_LABEL))
                == Some(name_node_str)
        })
        .collect();

    if filtered_pods.len() > 1 {
        warn!("Retrieved more than one coordinator pod. This is not supported and may lead to untested side effects. \
           Please specify only one coordinator in the custom resource via 'replicas=1'.");
    }

    for pod in &filtered_pods {
        let pod_name = match &pod.metadata.name {
            None => {
                return Err(ObjectWithoutName {
                    reference: ErrTrinoPodWithoutName.to_string(),
                })
            }
            Some(pod_name) => pod_name.clone(),
        };

        let node_name = match pod.spec.as_ref().and_then(|spec| spec.node_name.clone()) {
            None => {
                debug!("Pod [{:?}] is does not have node_name set, might not be scheduled yet, aborting.. ",
                       pod_name);
                return Err(PodWithoutHostname { pod: pod_name });
            }
            Some(node_name) => node_name,
        };

        // TODO: how to handle https?
        if let Some(http_port) = extract_container_port(pod, APP_NAME, HTTP_PORT) {
            return Ok(Some(TrinoDiscovery {
                node_name,
                http_port,
                protocol: TrinoDiscoveryProtocol::Http,
            }));
        }
    }

    Ok(None)
}

/// Extract the container port `port_name` from a container with name `container_name`.
/// Returns None if not the port or container are not available.
///
/// # Arguments
///
/// * `pod` - The pod to extract the container port from
/// * `container_name` - The name of the container to search for.
/// * `port_name` - The name of the container port.
///
fn extract_container_port(pod: &Pod, container_name: &str, port_name: &str) -> Option<String> {
    if let Some(spec) = &pod.spec {
        for container in &spec.containers {
            if container.name != container_name {
                continue;
            }

            if let Some(port) = container.ports.as_ref().and_then(|ports| {
                ports
                    .iter()
                    .find(|port| port.name == Some(port_name.to_string()))
            }) {
                return Some(port.container_port.to_string());
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use indoc::indoc;
    use rstest::rstest;

    #[rstest]
    #[case::single_coordinator_pod(
    indoc! {"
        - apiVersion: v1
          kind: Pod
          metadata:
            name: test
            labels:
              app.kubernetes.io/name: trino
              app.kubernetes.io/role-group: default
              app.kubernetes.io/instance: test
              app.kubernetes.io/component: coordinator 
          spec:
            nodeName: worker-1.stackable.tech
            containers:
              - name: trino
                ports:
                  - containerPort: 8080
                    name: http
        - apiVersion: v1
          kind: Pod
          metadata:
            name: test
            labels:
              app.kubernetes.io/name: trino
              app.kubernetes.io/role-group: default
              app.kubernetes.io/instance: test
              app.kubernetes.io/component: worker 
          spec:
            nodeName: worker-2.stackable.tech
            containers:
              - name: trino
                ports:
                  - containerPort: 9090
                    name: http
    "},
    "http://worker-1.stackable.tech:8080"
    )]
    fn get_connection_string(#[case] trino_pods: &str, #[case] expected_result: &str) {
        let pods = parse_pod_list_from_yaml(trino_pods);

        let discovery = get_trino_discovery_from_pods(pods.as_slice())
            .expect("should not fail")
            .unwrap();
        assert_eq!(expected_result, discovery.connection_string());
    }

    #[rstest]
    #[case::missing_hostname(
    indoc! {"
        - apiVersion: v1
          kind: Pod
          metadata:
            name: test
            labels:
              app.kubernetes.io/name: trino
              app.kubernetes.io/role-group: default
              app.kubernetes.io/instance: test
              app.kubernetes.io/component: coordinator 
          spec:
            containers:
              - name: trino
                ports:
                  - containerPort: 8080
                    name: http
    "},
    )]
    fn get_connection_string_should_fail(#[case] trino_pods: &str) {
        let pods = parse_pod_list_from_yaml(trino_pods);
        let discovery = get_trino_discovery_from_pods(pods.as_slice());
        assert!(discovery.is_err())
    }

    #[rstest]
    #[case::missing_container(
    indoc! {"
        - apiVersion: v1
          kind: Pod
          metadata:
            name: test
            labels:
              app.kubernetes.io/name: trino
              app.kubernetes.io/role-group: default
              app.kubernetes.io/instance: test
              app.kubernetes.io/component: coordinator 
          spec:
            nodeName: worker-1.stackable.tech
            containers: []
    "},
    )]
    #[case::missing_correct_container_port(
    indoc! {"
        - apiVersion: v1
          kind: Pod
          metadata:
            name: test
            labels:
              app.kubernetes.io/name: trino
              app.kubernetes.io/role-group: default
              app.kubernetes.io/instance: test
              app.kubernetes.io/component: coordinator 
          spec:
            nodeName: worker-1.stackable.tech
            containers:
              - name: trino
                ports:
                  - containerPort: 8080
                    name: abc
    "},
    )]
    fn get_connection_string_should_be_none(#[case] trino_pods: &str) {
        let pods = parse_pod_list_from_yaml(trino_pods);
        let discovery = get_trino_discovery_from_pods(pods.as_slice());
        assert!(discovery.unwrap().is_none())
    }

    fn parse_pod_list_from_yaml(pod_config: &str) -> Vec<Pod> {
        let kube_pods: Vec<k8s_openapi::api::core::v1::Pod> =
            serde_yaml::from_str(pod_config).unwrap();
        kube_pods.iter().map(|pod| pod.to_owned()).collect()
    }
}
