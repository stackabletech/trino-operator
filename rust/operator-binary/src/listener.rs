use snafu::{ResultExt, Snafu};
use stackable_operator::{
    builder::{
        meta::ObjectMetaBuilder,
        pod::volume::{
            ListenerOperatorVolumeSourceBuilder, ListenerOperatorVolumeSourceBuilderError,
            ListenerReference,
        },
    },
    config::merge::Merge,
    crd::listener::v1alpha1::{Listener, ListenerPort, ListenerSpec},
    k8s_openapi::api::core::v1::PersistentVolumeClaim,
    kvp::{Labels, ObjectLabels},
    role_utils::RoleGroupRef,
};

use crate::crd::{TrinoRole, v1alpha1};

pub const LISTENER_VOLUME_NAME: &str = "listener";
pub const LISTENER_VOLUME_DIR: &str = "/stackable/listener";

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("listener object is missing metadata to build owner reference"))]
    ObjectMissingMetadataForOwnerRef {
        source: stackable_operator::builder::meta::Error,
    },

    #[snafu(display("failed to build listener object meta data"))]
    BuildObjectMeta {
        source: stackable_operator::builder::meta::Error,
    },

    #[snafu(display("failed to build listener volume"))]
    BuildListenerPersistentVolume {
        source: ListenerOperatorVolumeSourceBuilderError,
    },
}

pub fn build_group_listener(
    trino: &v1alpha1::TrinoCluster,
    object_labels: ObjectLabels<v1alpha1::TrinoCluster>,
    listener_class: String,
    listener_group_name: String,
) -> Result<Listener, Error> {
    Ok(Listener {
        metadata: ObjectMetaBuilder::new()
            .name_and_namespace(trino)
            .name(listener_group_name)
            .ownerreference_from_resource(trino, None, Some(true))
            .context(ObjectMissingMetadataForOwnerRefSnafu)?
            .with_recommended_labels(object_labels)
            .context(BuildObjectMetaSnafu)?
            .build(),
        spec: ListenerSpec {
            class_name: Some(listener_class),
            ports: Some(listener_ports(trino)),
            ..ListenerSpec::default()
        },
        status: None,
    })
}

pub fn build_group_listener_pvc(
    group_listener_name: &str,
    unversioned_recommended_labels: &Labels,
) -> Result<PersistentVolumeClaim, Error> {
    ListenerOperatorVolumeSourceBuilder::new(
        &ListenerReference::ListenerName(group_listener_name.to_string()),
        unversioned_recommended_labels,
    )
    .context(BuildListenerPersistentVolumeSnafu)?
    .build_pvc(LISTENER_VOLUME_NAME.to_string())
    .context(BuildListenerPersistentVolumeSnafu)
}

/// The name of the group-listener provided for a specific role-group.
/// Coordinator(s) will use this group listener so that only one load balancer
/// is needed (per role group).
pub fn group_listener_name(
    role: &TrinoRole,
    role_group_ref: &RoleGroupRef<v1alpha1::TrinoCluster>,
) -> Option<String> {
    match role {
        TrinoRole::Coordinator => Some(role_group_ref.object_name()),
        TrinoRole::Worker => None,
    }
}

pub fn merged_listener_class(
    trino: &v1alpha1::TrinoCluster,
    role: &TrinoRole,
    rolegroup_name: &String,
) -> Option<String> {
    if role == &TrinoRole::Coordinator {
        if let Some(coordinators) = trino.spec.coordinators.as_ref() {
            let conf_defaults = Some("cluster-internal".to_string());
            let mut conf_role = coordinators.config.config.listener_class.to_owned();
            let mut conf_rolegroup = coordinators
                .role_groups
                .get(rolegroup_name)
                .map(|rg| rg.config.config.listener_class.clone())
                // TODO: Discuss in review
                // This should always be Some() due to the reconcile loop (role, role_group) in controller.rs
                // We do not want to use expect() here since its only a 99.99%. E.g. probably not possible to apply
                // and empty string / null via yaml, but could be via json - not sure?
                .unwrap_or_default();

            conf_role.merge(&conf_defaults);
            conf_rolegroup.merge(&conf_role);

            tracing::debug!("Merged listener-class: {:?}", conf_rolegroup);
            conf_rolegroup
        } else {
            None
        }
    } else {
        None
    }
}

/// We only use the http/https port here and intentionally omit the metrics one.
fn listener_ports(trino: &v1alpha1::TrinoCluster) -> Vec<ListenerPort> {
    let name = trino.exposed_protocol().to_string();
    let port = trino.exposed_port().into();

    vec![ListenerPort {
        name,
        port,
        protocol: Some("TCP".to_string()),
    }]
}
