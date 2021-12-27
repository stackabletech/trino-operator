use std::{collections::BTreeSet, num::TryFromIntError};

use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::{
    builder::{ConfigMapBuilder, ObjectMetaBuilder},
    k8s_openapi::api::core::v1::{ConfigMap, Endpoints, Service},
    kube::{self, runtime::reflector::ObjectRef, Resource, ResourceExt},
};


use crate::{trino_controller::trino_version, APP_NAME, APP_PORT};
use stackable_trino_crd::TrinoCluster;


#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("object {} is missing metadata to build owner reference", zk))]
    ObjectMissingMetadataForOwnerRef {
        source: stackable_operator::error::Error,
        trino: ObjectRef<TrinoCluster>,
    },
        #[snafu(display("object has no name associated"))]
    NoName,
    #[snafu(display("object has no namespace associated"))]
    NoNamespace,
    #[snafu(display("failed to list expected pods"))]
    ExpectedPods {
        source: NoNamespace,
    },
    NoServicePort {
        port_name: String,
    },
    NoNodePort {
        port_name: String,
    },
    FindEndpoints {
        source: kube::Error,
    },
    InvalidNodePort {
        source: TryFromIntError,
    },
}

/*
/// Builds discovery [`ConfigMap`]s for connecting to a [`ZookeeperCluster`] for all expected scenarios
pub async fn build_discovery_configmaps(
    kube: &kube::Client,
    owner: &impl Resource<DynamicType = ()>,
    trino: &TrinoCluster,
    svc: &Service,
    chroot: Option<&str>,
) -> Result<Vec<ConfigMap>, Error> {
    let name = owner.name();
    Ok(vec![
        build_discovery_configmap(&name, owner, trino, pod_hosts(trino)?)?,
        build_discovery_configmap(
            &format!("{}-nodeport", name),
            owner,
            trino,
            chroot,
            nodeport_hosts(kube, svc, "zk").await?,
        )?,
    ])
}

/// Build a discovery [`ConfigMap`] containing information about how to connect to a certain [`TrinoCluster`]
///
/// `hosts` will usually come from either [`pod_hosts`] or [`nodeport_hosts`].
fn build_discovery_configmap(
    name: &str,
    owner: &impl Resource<DynamicType = ()>,
    zk: &TrinoCluster,
    hosts: impl IntoIterator<Item = (impl Into<String>, u16)>,
) -> Result<ConfigMap, Error> {
    // Write a connection string of the format that Java ZooKeeper client expects:
    // "{host1}:{port1},{host2:port2},.../{chroot}"
    // See https://zookeeper.apache.org/doc/current/apidocs/zookeeper-server/org/apache/zookeeper/ZooKeeper.html#ZooKeeper-java.lang.String-int-org.apache.zookeeper.Watcher-
    let mut conn_str = hosts
        .into_iter()
        .map(|(host, port)| format!("{}:{}", host.into(), port))
        .collect::<Vec<_>>()
        .join(",");
    if let Some(chroot) = chroot {
        if !chroot.starts_with('/') {
            return RelativeChroot { chroot }.fail();
        }
        conn_str.push_str(chroot);
    }
    Ok(ConfigMapBuilder::new()
        .metadata(
            ObjectMetaBuilder::new()
                .name_and_namespace(zk)
                .name(name)
                .ownerreference_from_resource(owner, None, Some(true))
                .with_context(|| ObjectMissingMetadataForOwnerRef {
                    zk: ObjectRef::from_obj(zk),
                })?
                .with_recommended_labels(
                    zk,
                    APP_NAME,
                    trino_version(zk).unwrap(),
                    &ZookeeperRole::Server.to_string(),
                    "discovery",
                )
                .build(),
        )
        .add_data("ZOOKEEPER", conn_str)
        .build()
        .unwrap())
}

/// Lists all Pods FQDNs expected to host the [`ZookeeperCluster`]
fn pod_hosts(zk: &ZookeeperCluster) -> Result<impl IntoIterator<Item = (String, u16)> + '_, Error> {
    Ok(zk
        .pods()
        .context(ExpectedPods)?
        .into_iter()
        .map(|pod_ref| (pod_ref.fqdn(), APP_PORT)))
}

/// Lists all nodes currently hosting Pods participating in the [`Service`]
async fn nodeport_hosts(
    kube: &kube::Client,
    svc: &Service,
    port_name: &str,
) -> Result<impl IntoIterator<Item = (String, u16)>, Error> {
    let ns = svc.metadata.namespace.as_deref().context(NoNamespace)?;
    let endpointses = kube::Api::<Endpoints>::namespaced(kube.clone(), ns);
    let svc_port = svc
        .spec
        .as_ref()
        .and_then(|svc_spec| {
            svc_spec
                .ports
                .as_ref()?
                .iter()
                .find(|port| port.name.as_deref() == Some("zk"))
        })
        .context(NoServicePort { port_name })?;
    let node_port = svc_port.node_port.context(NoNodePort { port_name })?;
    let endpoints = endpointses
        .get(svc.metadata.name.as_deref().context(NoName)?)
        .await
        .context(FindEndpoints)?;
    let nodes = endpoints
        .subsets
        .into_iter()
        .flatten()
        .flat_map(|subset| subset.addresses)
        .flatten()
        .flat_map(|addr| addr.node_name);
    let addrs = nodes
        .map(|node| Ok((node, node_port.try_into().context(InvalidNodePort)?)))
        .collect::<Result<BTreeSet<_>, _>>()?;
    Ok(addrs)
}


 */