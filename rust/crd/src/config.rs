use crate::{
    ENV_INTERNAL_SECRET, ENV_TLS_STORE_SECRET, HTTPS_PORT, HTTP_SERVER_HTTPS_ENABLED,
    HTTP_SERVER_HTTPS_KEYSTORE_KEY, HTTP_SERVER_HTTPS_PORT, HTTP_SERVER_KEYSTORE_PATH,
    INTERNAL_COMMUNICATION_HTTPS_KEYSTORE_KEY, INTERNAL_COMMUNICATION_HTTPS_KEYSTORE_PATH,
    INTERNAL_COMMUNICATION_HTTPS_TRUSTSTORE_KEY, INTERNAL_COMMUNICATION_HTTPS_TRUSTSTORE_PATH,
    INTERNAL_COMMUNICATION_SHARED_SECRET, NODE_INTERNAL_ADDRESS_SOURCE,
    NODE_INTERNAL_ADDRESS_SOURCE_FQDN, TLS_INTERNAL_CLIENT_DIR, TLS_INTERNAL_SHARED_SECRET_DIR,
};
use std::collections::BTreeMap;

pub fn internal_tls_config(config: &mut BTreeMap<String, Option<String>>) {
    config.insert(
        HTTP_SERVER_HTTPS_ENABLED.to_string(),
        Some(true.to_string()),
    );
    config.insert(
        HTTP_SERVER_HTTPS_PORT.to_string(),
        Some(HTTPS_PORT.to_string()),
    );
    config.insert(
        INTERNAL_COMMUNICATION_SHARED_SECRET.to_string(),
        Some(format!("${{ENV:{secret}}}", secret = ENV_INTERNAL_SECRET)),
    );
    config.insert(
        INTERNAL_COMMUNICATION_HTTPS_KEYSTORE_PATH.to_string(),
        Some(format!("{}/keystore.p12", TLS_INTERNAL_SHARED_SECRET_DIR)),
    );
    config.insert(
        INTERNAL_COMMUNICATION_HTTPS_KEYSTORE_KEY.to_string(),
        Some(format!("${{ENV:{secret}}}", secret = ENV_TLS_STORE_SECRET)),
    );
    config.insert(
        INTERNAL_COMMUNICATION_HTTPS_TRUSTSTORE_PATH.to_string(),
        Some(format!("{}/truststore.p12", TLS_INTERNAL_SHARED_SECRET_DIR)),
    );
    config.insert(
        INTERNAL_COMMUNICATION_HTTPS_TRUSTSTORE_KEY.to_string(),
        Some(format!("${{ENV:{secret}}}", secret = ENV_TLS_STORE_SECRET)),
    );
    config.insert(
        NODE_INTERNAL_ADDRESS_SOURCE.to_string(),
        Some(NODE_INTERNAL_ADDRESS_SOURCE_FQDN.to_string()),
    );
}

pub fn client_tls_config(config: &mut BTreeMap<String, Option<String>>) {
    config.insert(
        HTTP_SERVER_HTTPS_ENABLED.to_string(),
        Some(true.to_string()),
    );
    config.insert(
        HTTP_SERVER_HTTPS_PORT.to_string(),
        Some(HTTPS_PORT.to_string()),
    );
    config.insert(
        HTTP_SERVER_KEYSTORE_PATH.to_string(),
        Some(format!("{}/{}", TLS_INTERNAL_CLIENT_DIR, "keystore.p12")),
    );
    config.insert(
        HTTP_SERVER_HTTPS_KEYSTORE_KEY.to_string(),
        Some(format!("${{ENV:{secret}}}", secret = ENV_TLS_STORE_SECRET)),
    );
}
