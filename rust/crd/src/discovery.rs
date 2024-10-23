use stackable_operator::utils::cluster_info::KubernetesClusterInfo;

use crate::{HTTPS_PORT, HTTP_PORT};

/// Reference to a single `Pod` that is a component of a [`crate::TrinoCluster`]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrinoPodRef {
    pub namespace: String,
    pub role_group_service_name: String,
    pub pod_name: String,
}

impl TrinoPodRef {
    pub fn fqdn(&self, cluster_info: &KubernetesClusterInfo) -> String {
        format!(
            "{pod_name}.{service_name}.{namespace}.svc.{cluster_domain}",
            pod_name = self.pod_name,
            service_name = self.role_group_service_name,
            namespace = self.namespace,
            cluster_domain = cluster_info.cluster_domain
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrinoDiscovery {
    pub pod_ref: TrinoPodRef,
    pub protocol: TrinoDiscoveryProtocol,
}

impl TrinoDiscovery {
    pub fn new(pod_ref: &TrinoPodRef, protocol: TrinoDiscoveryProtocol) -> Self {
        TrinoDiscovery {
            pod_ref: pod_ref.clone(),
            protocol,
        }
    }

    pub fn discovery_uri(&self, cluster_info: &KubernetesClusterInfo) -> String {
        format!(
            "{}://{}:{}",
            self.protocol,
            self.pod_ref.fqdn(cluster_info),
            self.protocol.port()
        )
    }
}

#[derive(Clone, Debug, strum::Display, Eq, Hash, PartialEq)]
pub enum TrinoDiscoveryProtocol {
    #[strum(serialize = "http")]
    Http,
    #[strum(serialize = "https")]
    Https,
}

impl TrinoDiscoveryProtocol {
    pub fn port(&self) -> u16 {
        match self {
            TrinoDiscoveryProtocol::Http => HTTP_PORT,
            TrinoDiscoveryProtocol::Https => HTTPS_PORT,
        }
    }
}
