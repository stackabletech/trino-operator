use std::str::FromStr;

use snafu::{ResultExt, Snafu};
use stackable_operator::{
    builder::pod::volume::{ListenerOperatorVolumeSourceBuilder, ListenerReference},
    crd::listener::v1alpha1::{Listener, ListenerPort, ListenerSpec},
    k8s_openapi::api::core::v1::PersistentVolumeClaim,
    kvp::Labels,
    v2::types::kubernetes::{ListenerClassName, VolumeName},
};

use crate::{
    controller::{ValidatedCluster, build::ports},
    crd::TrinoRole,
};

stackable_operator::constant!(pub LISTENER_VOLUME_NAME: VolumeName = "listener");
pub const LISTENER_VOLUME_DIR: &str = "/stackable/listener";

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("failed to build listener volume"))]
    BuildListenerPersistentVolume {
        source: stackable_operator::builder::pod::volume::ListenerOperatorVolumeSourceBuilderError,
    },
}

pub fn build_group_listener(
    cluster: &ValidatedCluster,
    recommended_labels: Labels,
    listener_class: &ListenerClassName,
    listener_group_name: String,
) -> Listener {
    Listener {
        metadata: cluster
            .object_meta(listener_group_name, recommended_labels)
            .build(),
        spec: ListenerSpec {
            class_name: Some(listener_class.to_string()),
            ports: Some(listener_ports(cluster)),
            ..ListenerSpec::default()
        },
        status: None,
    }
}

pub fn build_group_listener_pvc(
    group_listener_name: &str,
    unversioned_recommended_labels: &Labels,
) -> Result<PersistentVolumeClaim, Error> {
    ListenerOperatorVolumeSourceBuilder::new(
        &ListenerReference::ListenerName(group_listener_name.to_string()),
        unversioned_recommended_labels,
    )
    .build_pvc(LISTENER_VOLUME_NAME.to_string())
    .context(BuildListenerPersistentVolumeSnafu)
}

/// The name of the group-listener provided for a specific role-group.
/// Coordinator(s) will use this group listener so that only one load balancer
/// is needed (per role group).
pub fn group_listener_name(cluster: &ValidatedCluster, role: &TrinoRole) -> Option<String> {
    match role {
        TrinoRole::Coordinator => Some(format!(
            "{cluster_name}-{role}",
            cluster_name = cluster.name
        )),
        TrinoRole::Worker => None,
    }
}

/// The listener volume name depending on the role
pub fn secret_volume_listener_scope(role: &TrinoRole) -> Option<String> {
    match role {
        TrinoRole::Coordinator => Some(LISTENER_VOLUME_NAME.to_string()),
        TrinoRole::Worker => None,
    }
}

/// We only use the http/https port here and intentionally omit the metrics one.
fn listener_ports(cluster: &ValidatedCluster) -> Vec<ListenerPort> {
    let name = ports::exposed_protocol(cluster).to_string();
    let port = ports::exposed_port(cluster).into();

    vec![ListenerPort {
        name,
        port,
        protocol: Some("TCP".to_string()),
    }]
}
