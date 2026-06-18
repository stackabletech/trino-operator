//! The dereference step in the TrinoCluster controller
//!
//! Fetches all Kubernetes objects referenced by the TrinoCluster spec and returns them in
//! [`DereferencedObjects`]. The functions called here (`CatalogConfig::from_catalog`,
//! `TrinoOpaConfig::from_opa_config`, `ResolvedFaultTolerantExecutionConfig::from_config`,
//! `ResolvedClientProtocolConfig::from_config`) currently mix fetching and validation; their
//! outputs are treated as "dereferenced" for now. Splitting those helpers is a follow-up.

use std::{num::ParseIntError, str::FromStr};

use snafu::{ResultExt, Snafu};
use stackable_operator::{
    client::Client, kube::runtime::reflector::ObjectRef, v2::controller_utils::get_namespace,
};

use crate::{
    authorization::opa::TrinoOpaConfig,
    catalog::{FromTrinoCatalogError, config::CatalogConfig},
    config::{
        client_protocol::{self, ResolvedClientProtocolConfig},
        fault_tolerant_execution::{self, ResolvedFaultTolerantExecutionConfig},
    },
    crd::{
        authentication::{ResolvedAuthenticationClassRef, resolve_authentication_classes},
        catalog, v1alpha1,
    },
};

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("failed to get namespace"))]
    GetNamespace {
        source: stackable_operator::v2::controller_utils::Error,
    },

    #[snafu(display("failed to retrieve AuthenticationClass"))]
    AuthenticationClassRetrieval {
        source: crate::crd::authentication::Error,
    },

    #[snafu(display("failed to get associated TrinoCatalogs"))]
    GetCatalogs {
        source: stackable_operator::client::Error,
    },

    #[snafu(display("failed to parse {catalog}"))]
    ParseCatalog {
        source: FromTrinoCatalogError,
        catalog: ObjectRef<catalog::v1alpha1::TrinoCatalog>,
    },

    #[snafu(display("unable to parse Trino version: {product_version:?}"))]
    ParseTrinoVersion {
        source: ParseIntError,
        product_version: String,
    },

    #[snafu(display("failed to configure fault tolerant execution"))]
    FaultTolerantExecution {
        source: fault_tolerant_execution::Error,
    },

    #[snafu(display("failed to resolve client protocol configuration"))]
    ClientProtocolConfiguration { source: client_protocol::Error },

    #[snafu(display("invalid OpaConfig"))]
    InvalidOpaConfig {
        source: stackable_operator::commons::opa::Error,
    },
}

type Result<T, E = Error> = std::result::Result<T, E>;

/// Kubernetes objects referenced from the TrinoCluster spec, already fetched (and, for now, partly
/// validated by the existing helper functions).
pub struct DereferencedObjects {
    pub resolved_authentication_classes: Vec<ResolvedAuthenticationClassRef>,
    pub catalog_definitions: Vec<catalog::v1alpha1::TrinoCatalog>,
    pub catalogs: Vec<CatalogConfig>,
    pub trino_opa_config: Option<TrinoOpaConfig>,
    pub resolved_fte_config: Option<ResolvedFaultTolerantExecutionConfig>,
    pub resolved_client_protocol_config: Option<ResolvedClientProtocolConfig>,
}

/// Fetches all Kubernetes objects referenced from the [`v1alpha1::TrinoCluster`] spec.
pub async fn dereference(
    client: &Client,
    trino: &v1alpha1::TrinoCluster,
) -> Result<DereferencedObjects> {
    let namespace = get_namespace(trino).context(GetNamespaceSnafu)?;

    let resolved_authentication_classes =
        resolve_authentication_classes(client, trino.get_authentication())
            .await
            .context(AuthenticationClassRetrievalSnafu)?;

    let catalog_definitions = client
        .list_with_label_selector::<catalog::v1alpha1::TrinoCatalog>(
            namespace.as_ref(),
            &trino.spec.cluster_config.catalog_label_selector,
        )
        .await
        .context(GetCatalogsSnafu)?;

    let raw_product_version = trino.spec.image.product_version();
    let product_version = u16::from_str(raw_product_version).context(ParseTrinoVersionSnafu {
        product_version: raw_product_version,
    })?;

    let mut catalogs = Vec::with_capacity(catalog_definitions.len());
    for catalog in &catalog_definitions {
        let catalog_ref = ObjectRef::from_obj(catalog);
        let catalog_config =
            CatalogConfig::from_catalog(catalog, client, &namespace, product_version)
                .await
                .context(ParseCatalogSnafu {
                    catalog: catalog_ref,
                })?;
        catalogs.push(catalog_config);
    }

    let trino_opa_config = match trino.get_opa_config() {
        Some(opa_config) => Some(
            TrinoOpaConfig::from_opa_config(client, trino, &namespace, opa_config)
                .await
                .context(InvalidOpaConfigSnafu)?,
        ),
        None => None,
    };

    let resolved_fte_config = match trino.spec.cluster_config.fault_tolerant_execution.as_ref() {
        Some(fte_config) => Some(
            ResolvedFaultTolerantExecutionConfig::from_config(
                fte_config,
                Some(client),
                namespace.as_ref(),
            )
            .await
            .context(FaultTolerantExecutionSnafu)?,
        ),
        None => None,
    };

    let resolved_client_protocol_config = match trino.spec.cluster_config.client_protocol.as_ref() {
        Some(spooling_config) => Some(
            ResolvedClientProtocolConfig::from_config(
                spooling_config,
                Some(client),
                namespace.as_ref(),
            )
            .await
            .context(ClientProtocolConfigurationSnafu)?,
        ),
        None => None,
    };

    Ok(DereferencedObjects {
        resolved_authentication_classes,
        catalog_definitions,
        catalogs,
        trino_opa_config,
        resolved_fte_config,
        resolved_client_protocol_config,
    })
}
