pub(crate) mod password;

use crate::authentication::password::{
    file::FileAuthenticator, ldap::LdapAuthenticator, TrinoPasswordAuthentication,
    TrinoPasswordAuthenticator,
};

use snafu::{ResultExt, Snafu};
use stackable_operator::{
    builder::{ContainerBuilder, PodBuilder},
    commons::authentication::{AuthenticationClass, AuthenticationClassProvider},
    k8s_openapi::api::core::v1::{Container, Volume, VolumeMount},
    kube::{runtime::reflector::ObjectRef, ResourceExt},
    product_config,
};
use stackable_trino_crd::TrinoRole;
use std::collections::HashMap;
use strum::IntoEnumIterator;
use tracing::debug;

// trino properties
const HTTP_SERVER_AUTHENTICATION_TYPE: &str = "http-server.authentication.type";

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("The Trino Operator does not support the AuthenticationClass provider [{authentication_class_provider}] from AuthenticationClass [{authentication_class}]."))]
    AuthenticationClassProviderNotSupported {
        authentication_class_provider: String,
        authentication_class: ObjectRef<AuthenticationClass>,
    },
    #[snafu(display("Failed to format trino authentication java properties"))]
    FailedToWriteJavaProperties {
        source: product_config::writer::PropertiesWriterError,
    },
    #[snafu(display("Failed to configure trino password authentication"))]
    InvalidPasswordAuthenticationConfig { source: password::Error },
}

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Clone, Debug, Default)]
pub struct TrinoAuthenticationConfig {
    config_properties: HashMap<TrinoRole, HashMap<String, String>>,
    config_files: HashMap<TrinoRole, HashMap<String, String>>,
    volumes: Vec<Volume>,
    volume_mounts: HashMap<TrinoRole, HashMap<stackable_trino_crd::Container, Vec<VolumeMount>>>,
    sidecar_containers: HashMap<TrinoRole, Vec<Container>>,
}

impl TrinoAuthenticationConfig {
    pub fn add_authentication_config(
        &self,
        role: TrinoRole,
        pod_builder: &mut PodBuilder,
        prepare_builder: &mut ContainerBuilder,
        trino_builder: &mut ContainerBuilder,
        file_updater_builder: &mut ContainerBuilder,
    ) {
        // volumes
        pod_builder.add_volumes(self.volumes());
        // volume mounts
        for container in stackable_trino_crd::Container::iter() {
            let volume_mounts = self.volume_mounts(&role, &container);

            match container {
                stackable_trino_crd::Container::Prepare => {
                    prepare_builder.add_volume_mounts(volume_mounts);
                }
                stackable_trino_crd::Container::PasswordFileUpdater => {
                    file_updater_builder.add_volume_mounts(volume_mounts);
                }
                stackable_trino_crd::Container::Trino => {
                    trino_builder.add_volume_mounts(volume_mounts);
                }
                stackable_trino_crd::Container::Vector => {}
            }
        }
    }

    pub fn add_config_property(
        &mut self,
        role: TrinoRole,
        property_name: String,
        property_value: String,
    ) {
        self.config_properties
            .entry(role)
            .or_insert(HashMap::new())
            .insert(property_name, property_value);
    }

    pub fn add_config_file(&mut self, role: TrinoRole, file_name: String, file_content: String) {
        self.config_files
            .entry(role)
            .or_insert(HashMap::new())
            .insert(file_name, file_content);
    }

    pub fn add_volume(&mut self, volume: Volume) {
        if !self.volumes.contains(&volume) {
            self.volumes.push(volume);
        }
    }

    pub fn add_volume_mount(
        &mut self,
        role: TrinoRole,
        container: stackable_trino_crd::Container,
        volume_mount: VolumeMount,
    ) {
        let current_volume_mounts = self
            .volume_mounts
            .entry(role.clone())
            .or_insert_with(HashMap::new)
            .entry(container.clone())
            .or_insert_with(Vec::new);

        if !current_volume_mounts.contains(&volume_mount) {
            current_volume_mounts.push(volume_mount);
        }
    }

    pub fn add_sidecar_container(&mut self, role: TrinoRole, container: Container) {
        let containers_for_role = self.sidecar_containers.entry(role).or_insert_with(Vec::new);

        if !containers_for_role.contains(&container) {
            containers_for_role.push(container);
        }
    }

    pub fn config_properties(&self, role: &TrinoRole) -> HashMap<String, String> {
        self.config_properties
            .get(role)
            .cloned()
            .unwrap_or_else(HashMap::new)
    }

    pub fn config_files(&self, role: &TrinoRole) -> HashMap<String, String> {
        self.config_files
            .get(role)
            .cloned()
            .unwrap_or_else(HashMap::new)
    }

    pub fn volumes(&self) -> Vec<Volume> {
        self.volumes.clone()
    }

    pub fn volume_mounts(
        &self,
        role: &TrinoRole,
        container: &stackable_trino_crd::Container,
    ) -> Vec<VolumeMount> {
        if let Some(volume_mounts) = self.volume_mounts.get(role) {
            volume_mounts
                .get(container)
                .cloned()
                .unwrap_or_else(Vec::new)
        } else {
            Vec::new()
        }
    }

    pub fn sidecar_containers(&self, role: &TrinoRole) -> Vec<Container> {
        self.sidecar_containers
            .get(role)
            .cloned()
            .unwrap_or_else(Vec::new)
    }

    fn extend(&mut self, other: Self) {
        for (role, data) in other.config_properties {
            self.config_properties
                .entry(role)
                .or_insert_with(HashMap::new)
                .extend(data)
        }

        for (role, data) in other.config_files {
            self.config_files
                .entry(role)
                .or_insert_with(HashMap::new)
                .extend(data)
        }

        self.volumes.extend(other.volumes);

        for (role, containers) in other.volume_mounts {
            for (container, data) in containers {
                self.volume_mounts
                    .entry(role.clone())
                    .or_insert_with(HashMap::new)
                    .entry(container)
                    .or_insert_with(Vec::new)
                    .extend(data)
            }
        }

        for (role, data) in other.sidecar_containers {
            self.sidecar_containers
                .entry(role)
                .or_insert_with(Vec::new)
                .extend(data)
        }
    }
}

impl TryFrom<TrinoAuthenticationTypes> for TrinoAuthenticationConfig {
    type Error = Error;

    fn try_from(trino_auth: TrinoAuthenticationTypes) -> Result<Self, Self::Error> {
        let mut authentication_config = TrinoAuthenticationConfig::default();
        // Represents properties of "http-server.authentication.type".
        let mut http_server_authentication_types = vec![];

        for auth_type in &trino_auth.authentication_types {
            // Properties like PASSWORD, CERTIFICATE are only added once and the order is important
            // due to Trino starting to evaluate the authenticators depending on the given order
            if !http_server_authentication_types.contains(&auth_type.to_string()) {
                http_server_authentication_types.push(auth_type.to_string());
            }

            match auth_type {
                TrinoAuthenticationType::Password(password_auth) => authentication_config.extend(
                    password_auth
                        .password_authentication_config()
                        .context(InvalidPasswordAuthenticationConfigSnafu)?,
                ),
            }
        }

        authentication_config.add_config_property(
            TrinoRole::Coordinator,
            HTTP_SERVER_AUTHENTICATION_TYPE.to_string(),
            http_server_authentication_types.join(","),
        );

        debug!(
            "Final Trino authentication config: {:?}",
            authentication_config
        );

        Ok(authentication_config)
    }
}

#[derive(Clone, Debug, strum::Display)]
pub enum TrinoAuthenticationType {
    // #[strum(serialize = "CERTIFICATE")]
    // Certificate,
    // #[strum(serialize = "HEADER")]
    // Header,
    // #[strum(serialize = "JWT")]
    // Jwt,
    // #[strum(serialize = "KERBEROS")]
    // Kerberos,
    // #[strum(serialize = "OAUTH2")]
    // Oauth2,
    #[strum(serialize = "PASSWORD")]
    Password(TrinoPasswordAuthentication),
}

#[derive(Clone, Debug, Default)]
pub struct TrinoAuthenticationTypes {
    // All authentication classes sorted into the Trino interpretation
    authentication_types: Vec<TrinoAuthenticationType>,
}

impl TryFrom<Vec<AuthenticationClass>> for TrinoAuthenticationTypes {
    type Error = Error;

    fn try_from(auth_classes: Vec<AuthenticationClass>) -> std::result::Result<Self, Self::Error> {
        let mut authentication_types = vec![];
        let mut password_authenticators = vec![];

        for auth_class in auth_classes {
            let auth_class_name = auth_class.name_any();
            match auth_class.spec.provider {
                AuthenticationClassProvider::Static(provider) => {
                    password_authenticators.push(TrinoPasswordAuthenticator::File(
                        FileAuthenticator::new(auth_class_name, provider),
                    ));
                }
                AuthenticationClassProvider::Ldap(provider) => {
                    password_authenticators.push(TrinoPasswordAuthenticator::Ldap(
                        LdapAuthenticator::new(auth_class_name, provider),
                    ));
                }
                _ => AuthenticationClassProviderNotSupportedSnafu {
                    authentication_class_provider: auth_class.spec.provider.to_string(),
                    authentication_class: ObjectRef::<AuthenticationClass>::from_obj(&auth_class),
                }
                .fail()?,
            }
        }

        // Any password authenticators available?
        if !password_authenticators.is_empty() {
            authentication_types.push(TrinoAuthenticationType::Password(
                TrinoPasswordAuthentication::new(password_authenticators),
            ));
        }

        Ok(TrinoAuthenticationTypes {
            authentication_types,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stackable_operator::{
        commons::authentication::{
            static_::UserCredentialsSecretRef, AuthenticationClassSpec, LdapAuthenticationProvider,
            StaticAuthenticationProvider,
        },
        kube::core::ObjectMeta,
    };
    use stackable_trino_crd::RW_CONFIG_DIR_NAME;

    const FILE_AUTH_CLASS_1: &str = "file-auth-1";
    const FILE_AUTH_CLASS_2: &str = "file-auth-2";
    const LDAP_AUTH_CLASS_1: &str = "ldap-auth-1";
    const LDAP_AUTH_CLASS_2: &str = "ldap-auth-2";

    fn setup_file_auth_class(name: &str) -> AuthenticationClass {
        AuthenticationClass {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                ..ObjectMeta::default()
            },
            spec: AuthenticationClassSpec {
                provider: AuthenticationClassProvider::Static(StaticAuthenticationProvider {
                    user_credentials_secret: UserCredentialsSecretRef {
                        name: format!("{name}-secret"),
                    },
                }),
            },
        }
    }

    fn setup_ldap_auth_class(name: &str) -> AuthenticationClass {
        AuthenticationClass {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                ..ObjectMeta::default()
            },
            spec: AuthenticationClassSpec {
                provider: AuthenticationClassProvider::Ldap(LdapAuthenticationProvider {
                    hostname: "".to_string(),
                    port: None,
                    search_base: "".to_string(),
                    search_filter: "".to_string(),
                    ldap_field_names: Default::default(),
                    bind_credentials: None,
                    tls: None,
                }),
            },
        }
    }

    fn setup_authentication_classes() -> Vec<AuthenticationClass> {
        vec![
            setup_file_auth_class(FILE_AUTH_CLASS_1),
            setup_file_auth_class(FILE_AUTH_CLASS_2),
            setup_ldap_auth_class(LDAP_AUTH_CLASS_1),
            setup_ldap_auth_class(LDAP_AUTH_CLASS_2),
        ]
    }

    #[test]
    fn test_trino_password_authenticator_config_properties() {
        let trino_config_properties =
            TrinoAuthenticationTypes::try_from(setup_authentication_classes())
                .unwrap()
                .additional_config_properties(&TrinoRole::Coordinator);

        assert_eq!(
            trino_config_properties.get(HTTP_SERVER_AUTHENTICATION_TYPE),
            Some("PASSWORD".to_string()).as_ref(),
        );
        assert!(trino_config_properties
            .get(password::PASSWORD_AUTHENTICATOR_CONFIG_FILES)
            .is_some());
    }

    #[test]
    fn test_trino_password_authenticator_config_files() {
        let trino_config_files = TrinoAuthenticationTypes::try_from(setup_authentication_classes())
            .unwrap()
            .additional_config_files(&TrinoRole::Coordinator)
            .unwrap();

        assert_eq!(
            trino_config_files.get("file-authenticator.properties"),
            Some("file.password-file=/stackable/users/password.db\npassword-authenticator.name=file\n".to_string()).as_ref()
        );

        assert_eq!(
            trino_config_files.get("ldap-auth-1-ldap-authenticator.properties"),
            Some("ldap.allow-insecure=true\nldap.group-auth-pattern=(&(uid\\=${USER}))\nldap.url=ldap\\://\\:389\nldap.user-base-dn=\"\"\npassword-authenticator.name=ldap\n".to_string()).as_ref()
        );

        assert_eq!(
            trino_config_files.get("ldap-auth-2-ldap-authenticator.properties"),
            Some("ldap.allow-insecure=true\nldap.group-auth-pattern=(&(uid\\=${USER}))\nldap.url=ldap\\://\\:389\nldap.user-base-dn=\"\"\npassword-authenticator.name=ldap\n".to_string()).as_ref()
        );
    }
}
