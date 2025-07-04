use std::collections::BTreeMap;

use snafu::{ResultExt, Snafu};
use stackable_operator::{
    builder::meta::ObjectMetaBuilder,
    k8s_openapi::api::core::v1::{Service, ServicePort, ServiceSpec},
    kvp::{Label, ObjectLabels},
    role_utils::RoleGroupRef,
};

use crate::crd::{
    METRICS_PORT, METRICS_PORT_NAME, rolegroup_headless_service_name,
    rolegroup_metrics_service_name, v1alpha1,
};

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("object is missing metadata to build owner reference"))]
    ObjectMissingMetadataForOwnerRef {
        source: stackable_operator::builder::meta::Error,
    },

    #[snafu(display("failed to build Metadata"))]
    MetadataBuild {
        source: stackable_operator::builder::meta::Error,
    },

    #[snafu(display("failed to build Labels"))]
    LabelBuild {
        source: stackable_operator::kvp::LabelError,
    },
}

/// The rolegroup headless [`Service`] is a service that allows direct access to the instances of a certain rolegroup
/// This is mostly useful for internal communication between peers, or for clients that perform client-side load balancing.
pub fn build_rolegroup_headless_service(
    trino: &v1alpha1::TrinoCluster,
    role_group_ref: &RoleGroupRef<v1alpha1::TrinoCluster>,
    object_labels: ObjectLabels<v1alpha1::TrinoCluster>,
    selector: BTreeMap<String, String>,
) -> Result<Service, Error> {
    Ok(Service {
        metadata: ObjectMetaBuilder::new()
            .name_and_namespace(trino)
            .name(rolegroup_headless_service_name(
                &role_group_ref.object_name(),
            ))
            .ownerreference_from_resource(trino, None, Some(true))
            .context(ObjectMissingMetadataForOwnerRefSnafu)?
            .with_recommended_labels(object_labels)
            .context(MetadataBuildSnafu)?
            .build(),
        spec: Some(ServiceSpec {
            // Internal communication does not need to be exposed
            type_: Some("ClusterIP".to_string()),
            cluster_ip: Some("None".to_string()),
            ports: Some(headless_service_ports(trino)),
            selector: Some(selector),
            publish_not_ready_addresses: Some(true),
            ..ServiceSpec::default()
        }),
        status: None,
    })
}

/// The rolegroup metrics [`Service`] is a service that exposes metrics and a prometheus scraping label.
pub fn build_rolegroup_metrics_service(
    trino: &v1alpha1::TrinoCluster,
    role_group_ref: &RoleGroupRef<v1alpha1::TrinoCluster>,
    object_labels: ObjectLabels<v1alpha1::TrinoCluster>,
    selector: BTreeMap<String, String>,
) -> Result<Service, Error> {
    Ok(Service {
        metadata: ObjectMetaBuilder::new()
            .name_and_namespace(trino)
            .name(rolegroup_metrics_service_name(
                &role_group_ref.object_name(),
            ))
            .ownerreference_from_resource(trino, None, Some(true))
            .context(ObjectMissingMetadataForOwnerRefSnafu)?
            .with_recommended_labels(object_labels)
            .context(MetadataBuildSnafu)?
            .with_label(Label::try_from(("prometheus.io/scrape", "true")).context(LabelBuildSnafu)?)
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
    })
}

fn headless_service_ports(trino: &v1alpha1::TrinoCluster) -> Vec<ServicePort> {
    let name = trino.exposed_protocol().to_string();
    let port = trino.exposed_port().into();

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
