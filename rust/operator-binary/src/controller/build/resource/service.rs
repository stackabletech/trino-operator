use std::collections::BTreeMap;

use stackable_operator::{
    k8s_openapi::api::core::v1::{Service, ServicePort, ServiceSpec},
    kvp::Labels,
    v2::builder::service::{Scheme, Scraping, prometheus_annotations, prometheus_labels},
};

use crate::{
    controller::{RoleGroupName, ValidatedCluster, build::ports},
    crd::{METRICS_PORT, METRICS_PORT_NAME, TrinoRole},
};

/// The rolegroup headless [`Service`] is a service that allows direct access to the instances of a certain rolegroup
/// This is mostly useful for internal communication between peers, or for clients that perform client-side load balancing.
pub fn build_rolegroup_headless_service(
    cluster: &ValidatedCluster,
    role: &TrinoRole,
    role_group_name: &RoleGroupName,
    recommended_labels: &Labels,
    selector: BTreeMap<String, String>,
    ports: Vec<ServicePort>,
) -> Service {
    Service {
        metadata: cluster
            .object_meta(
                cluster
                    .resource_names(role, role_group_name)
                    .headless_service_name()
                    .to_string(),
                recommended_labels.clone(),
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
    recommended_labels: &Labels,
    selector: BTreeMap<String, String>,
) -> Service {
    Service {
        metadata: cluster
            .object_meta(
                cluster
                    .resource_names(role, role_group_name)
                    .metrics_service_name()
                    .to_string(),
                recommended_labels.clone(),
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
