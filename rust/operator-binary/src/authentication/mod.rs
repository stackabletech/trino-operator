//! This module computes all resources required for Trino authentication (e.g. PASSWORD, CERTIFICATE).
//!
//! Computes a `TrinoAuthenticationConfig` containing required resources like for all authentication
//! types like:
//! - config properties
//! - config files
//! - volume and volume mounts
//! - extra containers and commands
//!
pub(crate) mod password;

use crate::authentication::password::{
    file::FileAuthenticator, ldap::LdapAuthenticator, TrinoPasswordAuthentication,
    TrinoPasswordAuthenticator,
};

use snafu::{ResultExt, Snafu};
use stackable_operator::commons::product_image_selection::ResolvedProductImage;
use stackable_operator::{
    builder::{ContainerBuilder, PodBuilder},
    commons::authentication::{AuthenticationClass, AuthenticationClassProvider},
    k8s_openapi::api::core::v1::{Container, Volume, VolumeMount},
    kube::{runtime::reflector::ObjectRef, ResourceExt},
    product_config,
};
use stackable_trino_crd::TrinoRole;
use std::collections::{BTreeMap, HashMap};
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

/// This is the final product after iterating through all authenticators.
/// Contains all relevant information about config files, volumes etc. to enable authentication.
#[derive(Clone, Debug, Default)]
pub struct TrinoAuthenticationConfig {
    /// All config properties that have to be added to the `config.properties` of the given role
    config_properties: HashMap<TrinoRole, BTreeMap<String, String>>,
    /// All extra config files required for authentication for each role.
    config_files: HashMap<TrinoRole, BTreeMap<String, String>>,
    /// All extra container commands for a certain role and container
    commands: HashMap<TrinoRole, BTreeMap<stackable_trino_crd::Container, Vec<String>>>,
    /// Additional volumes like secret mounts, user file database etc.
    volumes: Vec<Volume>,
    /// Additional volume mounts for each role and container. Shared volumes have to be added
    /// manually in each container.
    volume_mounts: HashMap<TrinoRole, BTreeMap<stackable_trino_crd::Container, Vec<VolumeMount>>>,
    /// Additional side car container for the provided role
    sidecar_containers: HashMap<TrinoRole, Vec<Container>>,
}

impl TrinoAuthenticationConfig {
    pub fn new(
        resolved_product_image: &ResolvedProductImage,
        trino_auth: TrinoAuthenticationTypes,
    ) -> Result<Self, Error> {
        let mut authentication_config = TrinoAuthenticationConfig::default();
        // Represents properties of "http-server.authentication.type".
        // Properties like PASSWORD, CERTIFICATE are only added once and the order is important
        // due to Trino starting to evaluate the authenticators depending on the given order
        let mut http_server_authentication_types = vec![];

        for auth_type in &trino_auth.authentication_types {
            if !http_server_authentication_types.contains(&auth_type.to_string()) {
                http_server_authentication_types.push(auth_type.to_string());
            }

            match auth_type {
                TrinoAuthenticationType::Password(password_auth) => authentication_config.extend(
                    password_auth
                        .password_authentication_config(resolved_product_image)
                        .context(InvalidPasswordAuthenticationConfigSnafu)?,
                ),
            }
        }

        if !http_server_authentication_types.is_empty() {
            authentication_config.add_config_property(
                TrinoRole::Coordinator,
                HTTP_SERVER_AUTHENTICATION_TYPE.to_string(),
                http_server_authentication_types.join(","),
            );
        }

        debug!(
            "Final Trino authentication config: {:?}",
            authentication_config
        );

        Ok(authentication_config)
    }

    /// Automatically add volumes, volume mounts, commands and containers to
    /// the respective pod / container builders.
    pub fn add_authentication_pod_and_volume_config(
        &self,
        role: TrinoRole,
        pod_builder: &mut PodBuilder,
        prepare_builder: &mut ContainerBuilder,
        trino_builder: &mut ContainerBuilder,
    ) {
        // volumes
        pod_builder.add_volumes(self.volumes());

        let affected_containers = vec![
            stackable_trino_crd::Container::Prepare,
            stackable_trino_crd::Container::Trino,
        ];

        for container in &affected_containers {
            let volume_mounts = self.volume_mounts(&role, container);

            match container {
                stackable_trino_crd::Container::Prepare => {
                    prepare_builder.add_volume_mounts(volume_mounts);
                }
                stackable_trino_crd::Container::Trino => {
                    trino_builder.add_volume_mounts(volume_mounts);
                }
                // handled internally
                stackable_trino_crd::Container::PasswordFileUpdater => {}
                // nothing to do here
                stackable_trino_crd::Container::Vector => {}
            }
        }

        // containers
        for container in self.sidecar_containers(&role) {
            pod_builder.add_container(container);
        }
    }

    /// Add a key value pair to the Trino `config.properties` for a given role.
    pub fn add_config_property(
        &mut self,
        role: TrinoRole,
        property_name: String,
        property_value: String,
    ) {
        self.config_properties
            .entry(role)
            .or_insert(BTreeMap::new())
            .insert(property_name, property_value);
    }

    /// Add config file for a given role. The file_content must already be formatted to its final
    /// representation in the file.
    pub fn add_config_file(&mut self, role: TrinoRole, file_name: String, file_content: String) {
        self.config_files
            .entry(role)
            .or_insert(BTreeMap::new())
            .insert(file_name, file_content);
    }

    /// Add additional commands for a given role and container.
    pub fn add_commands(
        &mut self,
        role: TrinoRole,
        container: stackable_trino_crd::Container,
        commands: Vec<String>,
    ) {
        self.commands
            .entry(role)
            .or_insert(BTreeMap::new())
            .entry(container)
            .or_insert(Vec::new())
            .extend(commands)
    }

    /// Add an additional volume for the pod builder.
    pub fn add_volume(&mut self, volume: Volume) {
        if !self.volumes.contains(&volume) {
            self.volumes.push(volume);
        }
    }

    /// Add an additional volume mount for a role and container.
    /// Volume mounts are only added once and filtered for duplicates.
    pub fn add_volume_mount(
        &mut self,
        role: TrinoRole,
        container: stackable_trino_crd::Container,
        volume_mount: VolumeMount,
    ) {
        let current_volume_mounts = self
            .volume_mounts
            .entry(role)
            .or_insert_with(BTreeMap::new)
            .entry(container)
            .or_insert_with(Vec::new);

        if !current_volume_mounts.contains(&volume_mount) {
            current_volume_mounts.push(volume_mount);
        }
    }

    /// Add an extra sidecar container for a given role
    pub fn add_sidecar_container(&mut self, role: TrinoRole, container: Container) {
        let containers_for_role = self.sidecar_containers.entry(role).or_insert_with(Vec::new);

        if !containers_for_role.contains(&container) {
            containers_for_role.push(container);
        }
    }

    /// Retrieve additional properties for the `config.properties` file for a given role.
    pub fn config_properties(&self, role: &TrinoRole) -> BTreeMap<String, String> {
        self.config_properties
            .get(role)
            .cloned()
            .unwrap_or_default()
    }

    /// Retrieve additional config files for a given role.
    pub fn config_files(&self, role: &TrinoRole) -> BTreeMap<String, String> {
        self.config_files.get(role).cloned().unwrap_or_default()
    }

    /// Retrieve additional container commands for a given role and container.
    pub fn commands(
        &self,
        role: &TrinoRole,
        container: &stackable_trino_crd::Container,
    ) -> Vec<String> {
        self.commands
            .get(role)
            .cloned()
            .unwrap_or_default()
            .get(container)
            .cloned()
            .unwrap_or_default()
    }

    /// Retrieve all required volumes for the pod builder.
    pub fn volumes(&self) -> Vec<Volume> {
        self.volumes.clone()
    }

    /// Retrieve all required volume mounts for a given role.
    pub fn volume_mounts(
        &self,
        role: &TrinoRole,
        container: &stackable_trino_crd::Container,
    ) -> Vec<VolumeMount> {
        if let Some(volume_mounts) = self.volume_mounts.get(role) {
            volume_mounts.get(container).cloned().unwrap_or_default()
        } else {
            Vec::new()
        }
    }

    /// Retrieve all required sidecar containers for a given role.
    pub fn sidecar_containers(&self, role: &TrinoRole) -> Vec<Container> {
        self.sidecar_containers
            .get(role)
            .cloned()
            .unwrap_or_default()
    }

    /// This is a helper to easily extend/merge this struct
    fn extend(&mut self, other: Self) {
        for (role, data) in other.config_properties {
            self.config_properties
                .entry(role)
                .or_insert_with(BTreeMap::new)
                .extend(data)
        }

        for (role, data) in other.config_files {
            self.config_files
                .entry(role)
                .or_insert_with(BTreeMap::new)
                .extend(data)
        }

        self.volumes.extend(other.volumes);

        for (role, containers) in other.commands {
            for (container, commands) in containers {
                self.commands
                    .entry(role.clone())
                    .or_insert_with(BTreeMap::new)
                    .entry(container)
                    .or_insert_with(Vec::new)
                    .extend(commands)
            }
        }

        for (role, containers) in other.volume_mounts {
            for (container, data) in containers {
                self.volume_mounts
                    .entry(role.clone())
                    .or_insert_with(BTreeMap::new)
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

/// Representation of all Trino authentication types (e.g. PASSWORD).
/// One authentication type may have multiple authenticators (e.g. file, ldap).
/// These authenticators are summarized and handled in their respective struct.
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

/// Helper for AuthenticationClass conversion.
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
    use stackable_operator::commons::secret_class::SecretClassVolume;
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
                        name: name.to_string(),
                    },
                }),
            },
        }
    }

    fn setup_ldap_auth_class(
        name: &str,
        bind_credentials: Option<SecretClassVolume>,
    ) -> AuthenticationClass {
        AuthenticationClass {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                ..ObjectMeta::default()
            },
            spec: AuthenticationClassSpec {
                provider: AuthenticationClassProvider::Ldap(LdapAuthenticationProvider {
                    hostname: "host".to_string(),
                    port: None,
                    search_base: "".to_string(),
                    search_filter: "".to_string(),
                    ldap_field_names: Default::default(),
                    bind_credentials,
                    tls: None,
                }),
            },
        }
    }

    fn resolved_product_image() -> ResolvedProductImage {
        ResolvedProductImage {
            product_version: "".to_string(),
            app_version_label: "".to_string(),
            image: "".to_string(),
            image_pull_policy: "".to_string(),
            pull_secrets: None,
        }
    }

    fn setup_authentication_config() -> TrinoAuthenticationConfig {
        let auth_classes = vec![
            setup_file_auth_class(FILE_AUTH_CLASS_1),
            setup_file_auth_class(FILE_AUTH_CLASS_2),
            setup_ldap_auth_class(LDAP_AUTH_CLASS_1, None),
            setup_ldap_auth_class(LDAP_AUTH_CLASS_2, None),
        ];

        TrinoAuthenticationConfig::new(
            &resolved_product_image(),
            TrinoAuthenticationTypes::try_from(auth_classes).unwrap(),
        )
        .unwrap()
    }

    fn setup_authentication_config_bind_credentials() -> TrinoAuthenticationConfig {
        let bind_credentials = SecretClassVolume {
            secret_class: "secret_class".to_string(),
            scope: None,
        };

        let auth_classes = vec![
            setup_file_auth_class(FILE_AUTH_CLASS_1),
            setup_file_auth_class(FILE_AUTH_CLASS_2),
            setup_ldap_auth_class(LDAP_AUTH_CLASS_1, Some(bind_credentials.clone())),
            setup_ldap_auth_class(LDAP_AUTH_CLASS_2, Some(bind_credentials)),
        ];

        TrinoAuthenticationConfig::new(
            &resolved_product_image(),
            TrinoAuthenticationTypes::try_from(auth_classes).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn test_trino_password_authenticator_config_properties() {
        let config_properties =
            setup_authentication_config().config_properties(&TrinoRole::Coordinator);

        assert_eq!(
            config_properties.get(HTTP_SERVER_AUTHENTICATION_TYPE),
            Some("PASSWORD".to_string()).as_ref(),
        );

        let expected_config_file_names = format!(
            "\
        {RW_CONFIG_DIR_NAME}/{FILE_AUTH_CLASS_1}-password-file-auth.properties,\
        {RW_CONFIG_DIR_NAME}/{FILE_AUTH_CLASS_2}-password-file-auth.properties,\
        {RW_CONFIG_DIR_NAME}/{LDAP_AUTH_CLASS_1}-password-ldap-auth.properties,\
        {RW_CONFIG_DIR_NAME}/{LDAP_AUTH_CLASS_2}-password-ldap-auth.properties"
        );

        assert_eq!(
            config_properties.get(password::PASSWORD_AUTHENTICATOR_CONFIG_FILES),
            Some(expected_config_file_names).as_ref()
        );
    }

    #[test]
    fn test_trino_password_authenticator_config_files() {
        // Nothing for workers
        assert!(setup_authentication_config()
            .config_files(&TrinoRole::Worker)
            .is_empty());

        // coordinators
        let config_files = setup_authentication_config().config_files(&TrinoRole::Coordinator);

        assert_eq!(
            config_files.get(&format!("{FILE_AUTH_CLASS_1}-password-file-auth.properties")),
                Some(format!("file.password-file=/stackable/users/{FILE_AUTH_CLASS_1}.db\npassword-authenticator.name=file\n")).as_ref()
            );

        assert_eq!(
            config_files.get(&format!("{FILE_AUTH_CLASS_2}-password-file-auth.properties")),
            Some(format!("file.password-file=/stackable/users/{FILE_AUTH_CLASS_2}.db\npassword-authenticator.name=file\n")).as_ref()
        );

        assert_eq!(
                config_files.get(&format!("{LDAP_AUTH_CLASS_1}-password-ldap-auth.properties")),
                Some("ldap.allow-insecure=true\nldap.group-auth-pattern=(&(uid\\=${USER}))\nldap.url=ldap\\://host\\:389\nldap.user-base-dn=\"\"\npassword-authenticator.name=ldap\n".to_string()).as_ref()
            );

        assert_eq!(
            config_files.get(&format!("{LDAP_AUTH_CLASS_2}-password-ldap-auth.properties")),
                Some("ldap.allow-insecure=true\nldap.group-auth-pattern=(&(uid\\=${USER}))\nldap.url=ldap\\://host\\:389\nldap.user-base-dn=\"\"\npassword-authenticator.name=ldap\n".to_string()).as_ref()
            );
    }

    #[test]
    fn test_trino_password_authenticator_volumes() {
        // coordinators
        let volumes = setup_authentication_config().volumes();

        assert!(!volumes.is_empty());

        // One user password db volume
        assert_eq!(volumes.iter().filter(|v| v.name == "users").count(), 1);

        // 2 file auth secret mounts
        assert_eq!(
            volumes
                .iter()
                .filter(|v| v.name == format!("{FILE_AUTH_CLASS_1}")
                    || v.name == format!("{FILE_AUTH_CLASS_2}"))
                .count(),
            2
        );
    }

    #[test]
    fn test_trino_password_authenticator_volume_mounts() {
        // nothing for workers
        assert!(setup_authentication_config()
            .volume_mounts(&TrinoRole::Worker, &stackable_trino_crd::Container::Trino,)
            .is_empty());
        assert!(setup_authentication_config()
            .volume_mounts(&TrinoRole::Worker, &stackable_trino_crd::Container::Prepare,)
            .is_empty());

        // coordinator - main container
        let coordinator_main_mounts = setup_authentication_config().volume_mounts(
            &TrinoRole::Coordinator,
            &stackable_trino_crd::Container::Trino,
        );

        // we expect one user password db mount
        assert_eq!(coordinator_main_mounts.len(), 1);
        assert_eq!(coordinator_main_mounts.get(0).unwrap().name, "users");
        assert_eq!(
            coordinator_main_mounts.get(0).unwrap().mount_path,
            "/stackable/users"
        );
    }

    #[test]
    fn test_trino_password_authenticator_commands() {
        let auth_config = setup_authentication_config();
        let auth_config_with_ldap_bind = setup_authentication_config_bind_credentials();

        // nothing for workers
        assert!(auth_config
            .commands(&TrinoRole::Worker, &stackable_trino_crd::Container::Trino)
            .is_empty());
        assert!(auth_config_with_ldap_bind
            .commands(&TrinoRole::Worker, &stackable_trino_crd::Container::Trino)
            .is_empty());

        // we expect 0 entries because no bind credentials env export
        assert_eq!(
            auth_config
                .commands(
                    &TrinoRole::Coordinator,
                    &stackable_trino_crd::Container::Trino
                )
                .len(),
            0
        );

        // we expect 4 entries because of 2x user:password bind credential env export
        assert_eq!(
            auth_config_with_ldap_bind
                .commands(
                    &TrinoRole::Coordinator,
                    &stackable_trino_crd::Container::Trino
                )
                .len(),
            4
        );
    }

    #[test]
    fn test_trino_password_authenticator_sidecar_containers() {
        let auth_config = setup_authentication_config();
        // expect one file user password db update container
        assert_eq!(auth_config.sidecar_containers.len(), 1);
    }
}
