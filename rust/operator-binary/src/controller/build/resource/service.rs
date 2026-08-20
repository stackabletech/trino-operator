use std::collections::BTreeMap;

use stackable_operator::{
    k8s_openapi::api::core::v1::{Service, ServicePort, ServiceSpec},
    v2::builder::service::{Scheme, Scraping, prometheus_annotations, prometheus_labels},
};

use crate::{
    controller::{
        RoleGroupName, ValidatedCluster,
        build::{object_meta, ports, recommended_labels_for_role_group_resources},
    },
    crd::{METRICS_PORT, METRICS_PORT_NAME, TrinoRole},
};

/// The rolegroup headless [`Service`] is a service that allows direct access to the instances of a certain rolegroup
/// This is mostly useful for internal communication between peers, or for clients that perform client-side load balancing.
pub fn build_rolegroup_headless_service(
    cluster: &ValidatedCluster,
    role: &TrinoRole,
    role_group_name: &RoleGroupName,
    selector: BTreeMap<String, String>,
    ports: Vec<ServicePort>,
) -> Service {
    Service {
        metadata: object_meta(
            cluster,
            cluster
                .role_group_resource_names(role, role_group_name)
                .headless_service_name()
                .to_string(),
            recommended_labels_for_role_group_resources(cluster, role, role_group_name),
        )
        .build(),
        spec: Some(ServiceSpec {
            // Internal communication does not need to be exposed
            type_: Some("ClusterIP".to_string()),
            cluster_ip: Some("None".to_string()),
            ports: Some(ports),
            selector: Some(selector),
            publish_not_ready_addresses: Some(true),
            ..ServiceSpec::default()
        }),
        status: None,
    }
}

/// The rolegroup metrics [`Service`] is a service that exposes metrics and a prometheus scraping label.
pub fn build_rolegroup_metrics_service(
    cluster: &ValidatedCluster,
    role: &TrinoRole,
    role_group_name: &RoleGroupName,
    selector: BTreeMap<String, String>,
) -> Service {
    Service {
        metadata: object_meta(
            cluster,
            cluster
                .role_group_resource_names(role, role_group_name)
                .metrics_service_name()
                .to_string(),
            recommended_labels_for_role_group_resources(cluster, role, role_group_name),
        )
        .with_labels(prometheus_labels(&Scraping::Enabled))
        .with_annotations(prometheus_annotations(
            &Scraping::Enabled,
            &Scheme::Http,
            "/metrics",
            &METRICS_PORT,
        ))
        .build(),
        spec: Some(ServiceSpec {
            // Internal communication does not need to be exposed
            type_: Some("ClusterIP".to_string()),
            cluster_ip: Some("None".to_string()),
            ports: Some(metrics_service_ports()),
            selector: Some(selector),
            publish_not_ready_addresses: Some(true),
            ..ServiceSpec::default()
        }),
        status: None,
    }
}

pub(crate) fn headless_service_ports(cluster: &ValidatedCluster) -> Vec<ServicePort> {
    let name = ports::exposed_protocol(cluster).to_string();
    let port = ports::exposed_port(cluster).into();

    vec![ServicePort {
        name: Some(name),
        port,
        protocol: Some("TCP".to_string()),
        ..ServicePort::default()
    }]
}

fn metrics_service_ports() -> Vec<ServicePort> {
    vec![ServicePort {
        name: Some(METRICS_PORT_NAME.to_string()),
        port: METRICS_PORT.into(),
        protocol: Some("TCP".to_string()),
        ..ServicePort::default()
    }]
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use stackable_operator::v2::types::operator::RoleGroupName;

    use super::*;
    use crate::controller::{app_version_label, build::role_group_selector, validated_cluster};

    /// Every metrics Service must carry the Prometheus scrape label and the
    /// `prometheus.io/path|port|scheme|scrape` annotations, or Prometheus stops discovering the
    /// endpoints.
    #[test]
    fn test_rolegroup_metrics_service() {
        let cluster = validated_cluster();
        let role = TrinoRole::Coordinator;
        let role_group_name: RoleGroupName = "default".parse().expect("valid role group name");

        let selector = role_group_selector(&cluster, &role, &role_group_name);

        let service =
            build_rolegroup_metrics_service(&cluster, &role, &role_group_name, selector.into());

        assert_eq!(
            json!({
                "apiVersion": "v1",
                "kind": "Service",
                "metadata": {
                    "annotations": {
                        "prometheus.io/path": "/metrics",
                        "prometheus.io/port": "8081",
                        "prometheus.io/scheme": "http",
                        "prometheus.io/scrape": "true"
                    },
                    "labels": {
                        "app.kubernetes.io/component": "coordinator",
                        "app.kubernetes.io/instance": "simple-trino",
                        "app.kubernetes.io/managed-by": "trino.stackable.tech_trinocluster",
                        "app.kubernetes.io/name": "trino",
                        "app.kubernetes.io/role-group": "default",
                        "app.kubernetes.io/version": app_version_label("481"),
                        "prometheus.io/scrape": "true",
                        "stackable.tech/vendor": "Stackable"
                    },
                    "name": "simple-trino-coordinator-default-metrics",
                    "namespace": "default",
                    "ownerReferences": [
                        {
                            "apiVersion": "trino.stackable.tech/v1alpha1",
                            "controller": true,
                            "kind": "TrinoCluster",
                            "name": "simple-trino",
                            "uid": "e6ac237d-a6d4-43a1-8135-f36506110912"
                        }
                    ]
                },
                "spec": {
                    "clusterIP": "None",
                    "ports": [
                        {
                            "name": "metrics",
                            "port": 8081,
                            "protocol": "TCP"
                        }
                    ],
                    "publishNotReadyAddresses": true,
                    "selector": {
                        "app.kubernetes.io/component": "coordinator",
                        "app.kubernetes.io/instance": "simple-trino",
                        "app.kubernetes.io/name": "trino",
                        "app.kubernetes.io/role-group": "default"
                    },
                    "type": "ClusterIP"
                }
            }),
            serde_json::to_value(service).expect("must be serializable")
        );
    }
}
