use std::str::FromStr;

use snafu::{ResultExt, Snafu};
use stackable_operator::{
    builder::pod::volume::{ListenerOperatorVolumeSourceBuilder, ListenerReference},
    crd::listener::v1alpha1::{Listener, ListenerPort, ListenerSpec},
    k8s_openapi::api::core::v1::PersistentVolumeClaim,
    kvp::Labels,
    v2::types::{
        kubernetes::{ListenerClassName, ListenerName, VolumeName},
        operator::{ClusterName, RoleName},
    },
};

use crate::{
    controller::{
        ValidatedCluster,
        build::{object_meta, ports, recommended_labels_for_role_resources},
    },
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
    role: &TrinoRole,
    listener_class: &ListenerClassName,
    listener_group_name: &ListenerName,
) -> Listener {
    // The group listener is owned by the role (not a single role-group), so it carries the
    // role-level recommended labels.
    Listener {
        metadata: object_meta(
            cluster,
            listener_group_name.to_string(),
            recommended_labels_for_role_resources(cluster, role),
        )
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
    group_listener_name: &ListenerName,
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
///
/// The returned ListenerName is a lowercase RFC 1035 label name (checked by a unit test).
pub fn group_listener_name(cluster: &ValidatedCluster, role: &TrinoRole) -> Option<ListenerName> {
    const _: () = assert!(
        ClusterName::MAX_LENGTH + 1 /* dash */ + RoleName::MAX_LENGTH <= ListenerName::MAX_LENGTH,
        "The string `<cluster_name>-<role_name>` must not exceed the limit of Listener names."
    );
    // Both halves are RFC 1123 labels joined by a dash, which is a valid RFC 1123 subdomain.
    let _ = ClusterName::IS_RFC_1123_SUBDOMAIN_NAME;
    let _ = RoleName::IS_RFC_1123_LABEL_NAME;

    let role_name: &RoleName = role;
    match role {
        TrinoRole::Coordinator => Some(
            ListenerName::from_str(&format!(
                "{cluster_name}-{role_name}",
                cluster_name = cluster.name,
            ))
            .expect("is a valid Listener name"),
        ),
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use strum::IntoEnumIterator;

    use super::*;
    use crate::controller::{app_version_label, validated_cluster};

    #[test]
    fn test_constants() {
        // Test that dereferencing the constant does not panic.
        let _ = *LISTENER_VOLUME_NAME;
    }

    /// The group listener is a role-level (not role-group-level) resource, so it carries the
    /// role-resource recommended labels: a `component` label for the role and no `role-group`
    /// label.
    #[test]
    fn group_listener_carries_role_level_labels() {
        let cluster = validated_cluster();
        let role = TrinoRole::Coordinator;
        let listener_class: ListenerClassName = "cluster-internal"
            .parse()
            .expect("valid ListenerClass name");
        let listener_group_name =
            group_listener_name(&cluster, &role).expect("the coordinator has a group listener");

        let listener = build_group_listener(&cluster, &role, &listener_class, &listener_group_name);

        let expected_labels: BTreeMap<String, String> = [
            ("app.kubernetes.io/component", "coordinator".to_string()),
            ("app.kubernetes.io/instance", "simple-trino".to_string()),
            (
                "app.kubernetes.io/managed-by",
                "trino.stackable.tech_trinocluster".to_string(),
            ),
            ("app.kubernetes.io/name", "trino".to_string()),
            ("app.kubernetes.io/version", app_version_label("481")),
            ("stackable.tech/vendor", "Stackable".to_string()),
        ]
        .into_iter()
        .map(|(key, value)| (key.to_string(), value))
        .collect();
        assert_eq!(listener.metadata.labels, Some(expected_labels));
    }

    #[test]
    fn group_listener_name_is_rfc_1035_label_name() {
        // Every ClusterName is a valid RFC 1035 label name, so we use just some string with maximum
        // length.
        let _ = ClusterName::IS_RFC_1035_LABEL_NAME;
        let mut cluster = validated_cluster();
        cluster.name = ClusterName::from_str_unsafe(&"a".repeat(ClusterName::MAX_LENGTH));

        for role in TrinoRole::iter() {
            if let Some(group_listener_name) = group_listener_name(&cluster, &role) {
                assert!(
                    stackable_operator::validation::is_lowercase_rfc_1035_label(
                        group_listener_name.as_ref()
                    )
                    .is_ok()
                );
            }
        }
    }
}
