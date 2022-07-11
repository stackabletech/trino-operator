use crate::{HTTPS_PORT, HTTP_PORT};

/// Reference to a single `Pod` that is a component of a [`crate::TrinoCluster`]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrinoPodRef {
    pub namespace: String,
    pub role_group_service_name: String,
    pub pod_name: String,
}

impl TrinoPodRef {
    pub fn fqdn(&self) -> String {
        format!(
            "{}.{}.{}.svc.cluster.local",
            self.pod_name, self.role_group_service_name, self.namespace
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

    pub fn connection_string(&self) -> String {
        format!(
            "{}://{}:{}",
            self.protocol,
            self.pod_ref.fqdn(),
            self.protocol.port()
        )
    }

    pub fn unsecure_connection_string(&self) -> String {
        format!("http://{}:{}", self.pod_ref.fqdn(), HTTP_PORT)
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
