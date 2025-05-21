//! This module computes all resources required for Trino authentication (e.g. PASSWORD, OAUTH2).
//!
//! Computes a `TrinoAuthenticationConfig` containing required resources like for all authentication
//! types like:
//! - config properties
//! - config files
//! - volume and volume mounts
//! - extra containers and commands
//!
use std::collections::{BTreeMap, HashMap};

use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::{
    builder::{
        self,
        pod::{PodBuilder, container::ContainerBuilder},
    },
    commons::product_image_selection::ResolvedProductImage,
    crd::authentication::core,
    k8s_openapi::api::core::v1::{Container, EnvVar, Volume, VolumeMount},
    kube::{ResourceExt, runtime::reflector::ObjectRef},
};
use strum::EnumDiscriminants;
use tracing::trace;

use crate::{
    authentication::{
        oidc::{OidcAuthenticator, TrinoOidcAuthentication},
        password::{
            TrinoPasswordAuthentication, TrinoPasswordAuthenticator, file::FileAuthenticator,
            ldap::LdapAuthenticator,
        },
    },
    crd::{TrinoRole, authentication::ResolvedAuthenticationClassRef},
};

pub(crate) mod oidc;
pub(crate) mod password;

// trino properties
const HTTP_SERVER_AUTHENTICATION_TYPE: &str = "http-server.authentication.type";

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display(
        "The Trino Operator does not support the AuthenticationClass provider [{authentication_class_provider}] from AuthenticationClass [{authentication_class}]."
    ))]
    AuthenticationClassProviderNotSupported {
        authentication_class_provider: String,
        authentication_class: ObjectRef<core::v1alpha1::AuthenticationClass>,
    },

    #[snafu(display("Failed to format trino authentication java properties"))]
    FailedToWriteJavaProperties {
        source: product_config::writer::PropertiesWriterError,
    },

    #[snafu(display("Failed to configure trino password authentication"))]
    InvalidPasswordAuthenticationConfig { source: password::Error },

    #[snafu(display("Failed to configure trino OAuth2 authentication"))]
    InvalidOauth2AuthenticationConfig { source: oidc::Error },

    #[snafu(display(
        "OIDC authentication details not specified. The AuthenticationClass {auth_class_name:?} uses an OIDC provider, you need to specify OIDC authentication details (such as client credentials) as well"
    ))]
    OidcAuthenticationDetailsNotSpecified { auth_class_name: String },

    #[snafu(display("failed to add needed volume"))]
    AddVolume { source: builder::pod::Error },

    #[snafu(display("failed to add needed volumeMount"))]
    AddVolumeMount {
        source: builder::pod::container::Error,
    },
}

type Result<T, E = Error> = std::result::Result<T, E>;

/// This is the final product after iterating through all authenticators.
/// Contains all relevant information about config files, volumes etc. to enable authentication.
/// The `TrinoRole` map key is actually not required here since all authentication settings are
/// done in the coordinator. However, this implementation aims for a general implementation that
/// may be in parts reused in other operators.
#[derive(Clone, Debug, Default)]
pub struct TrinoAuthenticationConfig {
    /// All config properties that have to be added to the `config.properties` of the given role
    config_properties: HashMap<TrinoRole, BTreeMap<String, String>>,
    /// All extra config files required for authentication for each role.
    config_files: HashMap<TrinoRole, BTreeMap<String, String>>,
    /// Additional env variables for a certain role and container
    env_vars: HashMap<TrinoRole, BTreeMap<crate::crd::Container, Vec<EnvVar>>>,
    /// All extra container commands for a certain role and container
    commands: HashMap<TrinoRole, BTreeMap<crate::crd::Container, Vec<String>>>,
    /// Additional volumes like secret mounts, user file database etc.
    volumes: Vec<Volume>,
    /// Additional volume mounts for each role and container. Shared volumes have to be added
    /// manually in each container.
    volume_mounts: HashMap<TrinoRole, BTreeMap<crate::crd::Container, Vec<VolumeMount>>>,
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
        // Properties like PASSWORD, OAUTH2 are only added once and the order is important
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
                TrinoAuthenticationType::Oauth2(oauth2_auth) => authentication_config.extend(
                    oauth2_auth
                        .oauth2_authentication_config()
                        .context(InvalidOauth2AuthenticationConfigSnafu)?,
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

        trace!(
            "Final Trino authentication config: {:?}",
            authentication_config
        );

        Ok(authentication_config)
    }

    /// Automatically add volumes, volume mounts, commands and containers to
    /// the respective pod / container builders.
    pub fn add_authentication_pod_and_volume_config(
        &self,
        role: &TrinoRole,
        pod_builder: &mut PodBuilder,
        prepare_builder: &mut ContainerBuilder,
        trino_builder: &mut ContainerBuilder,
    ) -> Result<()> {
        // volumes
        pod_builder
            .add_volumes(self.volumes())
            .context(AddVolumeSnafu)?;

        let affected_containers =
            vec![crate::crd::Container::Prepare, crate::crd::Container::Trino];

        for container in &affected_containers {
            let volume_mounts = self.volume_mounts(role, container);

            match container {
                crate::crd::Container::Prepare => {
                    prepare_builder
                        .add_volume_mounts(volume_mounts)
                        .context(AddVolumeMountSnafu)?;
                }
                crate::crd::Container::Trino => {
                    trino_builder
                        .add_volume_mounts(volume_mounts)
                        .context(AddVolumeMountSnafu)?;
                }
                // handled internally
                crate::crd::Container::PasswordFileUpdater => {}
                // nothing to do here
                crate::crd::Container::Vector => {}
            }
        }

        Ok(())
    }

    /// Add required init / side car containers
    pub fn add_authentication_containers(&self, role: &TrinoRole, pod_builder: &mut PodBuilder) {
        // containers
        for container in self.sidecar_containers(role) {
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
            .or_default()
            .insert(property_name, property_value);
    }

    /// Add config file for a given role. The file_content must already be formatted to its final
    /// representation in the file.
    pub fn add_config_file(&mut self, role: TrinoRole, file_name: String, file_content: String) {
        self.config_files
            .entry(role)
            .or_default()
            .insert(file_name, file_content);
    }

    /// Add env variables for a given role and container.
    pub fn add_env_vars(
        &mut self,
        role: TrinoRole,
        container: crate::crd::Container,
        env_var: Vec<EnvVar>,
    ) {
        self.env_vars
            .entry(role)
            .or_default()
            .entry(container)
            .or_default()
            .extend(env_var)
    }

    /// Add additional commands for a given role and container.
    pub fn add_commands(
        &mut self,
        role: TrinoRole,
        container: crate::crd::Container,
        commands: Vec<String>,
    ) {
        self.commands
            .entry(role)
            .or_default()
            .entry(container)
            .or_default()
            .extend(commands)
    }

    /// Add an additional volume for the pod builder.
    pub fn add_volume(&mut self, volume: Volume) {
        if !self.volumes.iter().any(|v| v.name == volume.name) {
            self.volumes.push(volume);
        }
    }

    /// Add additional volumes for the pod builder.
    pub fn add_volumes(&mut self, volumes: Vec<Volume>) {
        for volume in volumes {
            self.add_volume(volume)
        }
    }

    /// Add an additional volume mount for a role and container.
    /// Volume mounts are only added once and filtered for duplicates.
    pub fn add_volume_mount(
        &mut self,
        role: TrinoRole,
        container: crate::crd::Container,
        volume_mount: VolumeMount,
    ) {
        let current_volume_mounts = self
            .volume_mounts
            .entry(role)
            .or_default()
            .entry(container)
            .or_default();

        if !current_volume_mounts
            .iter()
            .any(|vm| vm.name == volume_mount.name)
        {
            current_volume_mounts.push(volume_mount);
        }
    }

    /// Add additional volume mounts for a role and container.
    /// Volume mounts are only added once and filtered for duplicates.
    pub fn add_volume_mounts(
        &mut self,
        role: TrinoRole,
        container: crate::crd::Container,
        volume_mounts: Vec<VolumeMount>,
    ) {
        for volume_mount in volume_mounts {
            self.add_volume_mount(role.clone(), container.clone(), volume_mount);
        }
    }

    /// Add an extra sidecar container for a given role
    pub fn add_sidecar_container(&mut self, role: TrinoRole, container: Container) {
        let containers_for_role = self.sidecar_containers.entry(role).or_default();

        if !containers_for_role.iter().any(|c| c.name == container.name) {
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

    /// Retrieve additional env vars for a given role and container.
    pub fn env_vars(&self, role: &TrinoRole, container: &crate::crd::Container) -> Vec<EnvVar> {
        self.env_vars
            .get(role)
            .cloned()
            .unwrap_or_default()
            .get(container)
            .cloned()
            .unwrap_or_default()
    }

    /// Retrieve additional container commands for a given role and container.
    pub fn commands(&self, role: &TrinoRole, container: &crate::crd::Container) -> Vec<String> {
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
        container: &crate::crd::Container,
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
            self.config_properties.entry(role).or_default().extend(data)
        }

        for (role, data) in other.config_files {
            self.config_files.entry(role).or_default().extend(data)
        }

        for (role, containers) in other.env_vars {
            for (container, env_vars) in containers {
                self.env_vars
                    .entry(role.clone())
                    .or_default()
                    .entry(container)
                    .or_default()
                    .extend(env_vars)
            }
        }

        for (role, containers) in other.commands {
            for (container, commands) in containers {
                self.commands
                    .entry(role.clone())
                    .or_default()
                    .entry(container)
                    .or_default()
                    .extend(commands)
            }
        }

        self.volumes.extend(other.volumes);

        for (role, containers) in other.volume_mounts {
            for (container, data) in containers {
                self.volume_mounts
                    .entry(role.clone())
                    .or_default()
                    .entry(container)
                    .or_default()
                    .extend(data)
            }
        }

        for (role, data) in other.sidecar_containers {
            self.sidecar_containers
                .entry(role)
                .or_default()
                .extend(data)
        }
    }
}

/// Representation of all Trino authentication types (e.g. PASSWORD).
/// One authentication type may have multiple authenticators (e.g. file, ldap).
/// These authenticators are summarized and handled in their respective struct.
#[derive(Clone, Debug, strum::Display, EnumDiscriminants)]
pub enum TrinoAuthenticationType {
    // #[strum(serialize = "CERTIFICATE")]
    // Certificate,
    // #[strum(serialize = "HEADER")]
    // Header,
    // #[strum(serialize = "JWT")]
    // Jwt,
    // #[strum(serialize = "KERBEROS")]
    // Kerberos,
    #[strum(serialize = "OAUTH2")]
    Oauth2(TrinoOidcAuthentication),
    #[strum(serialize = "PASSWORD")]
    Password(TrinoPasswordAuthentication),
}

/// Helper for AuthenticationClass conversion.
#[derive(Clone, Debug, Default)]
pub struct TrinoAuthenticationTypes {
    // All authentication classes sorted into the Trino interpretation
    authentication_types: Vec<TrinoAuthenticationType>,
}

impl TrinoAuthenticationTypes {
    /// Helper method to store the order of provided AuthenticationClasses in the CRD.
    /// Trino will query all authentication methods in the order provided in
    /// "http-server.authentication.type".
    pub fn insert_auth_type_order(
        store: &mut Vec<TrinoAuthenticationTypeDiscriminants>,
        auth_type: TrinoAuthenticationTypeDiscriminants,
    ) {
        if !store.contains(&auth_type) {
            store.push(auth_type);
        }
    }
}

impl TryFrom<Vec<ResolvedAuthenticationClassRef>> for TrinoAuthenticationTypes {
    type Error = Error;

    fn try_from(
        resolved_auth_classes: Vec<ResolvedAuthenticationClassRef>,
    ) -> std::result::Result<Self, Self::Error> {
        let mut authentication_types = vec![];
        let mut authentication_types_order = Vec::<TrinoAuthenticationTypeDiscriminants>::new();

        let mut password_authenticators = vec![];
        // OAuth2 cannot be configured to have multiple IDPs and therefore does not need to be
        // a vector in comparison to password authentication (file, ldap).
        // This is still a vec to handle errors more granular in the OAuth2 module
        let mut oidc_authenticators = vec![];

        // Collect all provided AuthenticationClass providers into their respective authenticators
        for resolved_auth_class in resolved_auth_classes {
            let auth_class_name = resolved_auth_class.authentication_class.name_any();
            match resolved_auth_class.authentication_class.spec.provider {
                core::v1alpha1::AuthenticationClassProvider::Static(provider) => {
                    password_authenticators.push(TrinoPasswordAuthenticator::File(
                        FileAuthenticator::new(auth_class_name, provider),
                    ));

                    TrinoAuthenticationTypes::insert_auth_type_order(
                        &mut authentication_types_order,
                        TrinoAuthenticationTypeDiscriminants::Password,
                    );
                }
                core::v1alpha1::AuthenticationClassProvider::Ldap(provider) => {
                    password_authenticators.push(TrinoPasswordAuthenticator::Ldap(
                        LdapAuthenticator::new(auth_class_name, provider),
                    ));

                    TrinoAuthenticationTypes::insert_auth_type_order(
                        &mut authentication_types_order,
                        TrinoAuthenticationTypeDiscriminants::Password,
                    );
                }
                core::v1alpha1::AuthenticationClassProvider::Oidc(provider) => {
                    let oidc = resolved_auth_class.client_auth_options.context(
                        OidcAuthenticationDetailsNotSpecifiedSnafu {
                            auth_class_name: auth_class_name.clone(),
                        },
                    )?;
                    oidc_authenticators.push(OidcAuthenticator::new(
                        auth_class_name,
                        provider,
                        oidc.client_credentials_secret_ref,
                        oidc.extra_scopes,
                    ));

                    TrinoAuthenticationTypes::insert_auth_type_order(
                        &mut authentication_types_order,
                        TrinoAuthenticationTypeDiscriminants::Oauth2,
                    );
                }
                _ => AuthenticationClassProviderNotSupportedSnafu {
                    authentication_class_provider: resolved_auth_class
                        .authentication_class
                        .spec
                        .provider
                        .to_string(),
                    authentication_class:
                        ObjectRef::<core::v1alpha1::AuthenticationClass>::from_obj(
                            &resolved_auth_class.authentication_class,
                        ),
                }
                .fail()?,
            }
        }

        // We want to preserve the order of the provided AuthenticationClasses to determine
        // which AuthenticationMethod Trino will try first.
        for auth_type in authentication_types_order {
            match auth_type {
                TrinoAuthenticationTypeDiscriminants::Oauth2 => {
                    authentication_types.push(TrinoAuthenticationType::Oauth2(
                        TrinoOidcAuthentication::new(oidc_authenticators.clone()),
                    ));
                }
                TrinoAuthenticationTypeDiscriminants::Password => {
                    authentication_types.push(TrinoAuthenticationType::Password(
                        TrinoPasswordAuthentication::new(password_authenticators.clone()),
                    ));
                }
            }
        }

        Ok(TrinoAuthenticationTypes {
            authentication_types,
        })
    }
}

#[cfg(test)]
mod tests {
    use stackable_operator::crd::authentication::oidc;

    use super::*;
    use crate::crd::RW_CONFIG_DIR_NAME;

    const OIDC_AUTH_CLASS_1: &str = "oidc-auth-1";
    const FILE_AUTH_CLASS_1: &str = "file-auth-1";
    const FILE_AUTH_CLASS_2: &str = "file-auth-2";
    const LDAP_AUTH_CLASS_1: &str = "ldap-auth-1";
    const LDAP_AUTH_CLASS_2: &str = "ldap-auth-2";
    const HOST_NAME: &str = "my.server";
    const SEARCH_BASE: &str = "searchbase";

    fn setup_file_auth_class(name: &str) -> ResolvedAuthenticationClassRef {
        let input = deserialize(&format!(
            r#"
        metadata:
          name: {name}
        spec:
          provider:
            static:
              userCredentialsSecret:
                name: {name}
        "#
        ));

        ResolvedAuthenticationClassRef {
            authentication_class: input,
            client_auth_options: None,
        }
    }

    fn setup_ldap_auth_class(name: &str) -> ResolvedAuthenticationClassRef {
        let input = deserialize(&format!(
            r#"
        metadata:
          name: {name}
        spec:
          provider:
            ldap:
              hostname: {HOST_NAME}
              searchBase: {SEARCH_BASE}
        "#
        ));

        ResolvedAuthenticationClassRef {
            authentication_class: input,
            client_auth_options: None,
        }
    }

    fn setup_ldap_auth_class_with_bind_credentials_secret_class(
        name: &str,
        secret_class: &str,
    ) -> ResolvedAuthenticationClassRef {
        let input = deserialize(&format!(
            r#"
            apiVersion: authentication.stackable.tech/v1alpha1
            kind: AuthenticationClass
            metadata:
              name: {name}
            spec:
              provider:
                ldap:
                  hostname: {HOST_NAME}
                  searchBase: {SEARCH_BASE}
                  bindCredentials:
                    secretClass: {secret_class}
            "#
        ));

        ResolvedAuthenticationClassRef {
            authentication_class: input,
            client_auth_options: None,
        }
    }

    fn setup_oidc_auth_class(name: &str) -> ResolvedAuthenticationClassRef {
        let input = format!(
            r#"
            apiVersion: authentication.stackable.tech/v1alpha1
            kind: AuthenticationClass
            metadata:
              name: {name}
            spec:
              provider:
                oidc:
                  hostname: {HOST_NAME}
                  rootPath: /realms/master/
                  scopes: ["openid"]
                  principalClaim: preferred_username
            "#,
        );
        let deserializer = serde_yaml::Deserializer::from_str(&input);

        ResolvedAuthenticationClassRef {
            authentication_class: serde_yaml::with::singleton_map_recursive::deserialize(
                deserializer,
            )
            .unwrap(),
            client_auth_options: Some(oidc::v1alpha1::ClientAuthenticationOptions {
                client_credentials_secret_ref: "my-oidc-secret".to_string(),
                extra_scopes: Vec::new(),
                product_specific_fields: (),
            }),
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
            setup_oidc_auth_class(OIDC_AUTH_CLASS_1),
            setup_file_auth_class(FILE_AUTH_CLASS_1),
            setup_file_auth_class(FILE_AUTH_CLASS_2),
            setup_ldap_auth_class(LDAP_AUTH_CLASS_1),
            setup_ldap_auth_class(LDAP_AUTH_CLASS_2),
        ];

        TrinoAuthenticationConfig::new(
            &resolved_product_image(),
            TrinoAuthenticationTypes::try_from(auth_classes).unwrap(),
        )
        .unwrap()
    }

    fn setup_authentication_config_bind_credentials() -> TrinoAuthenticationConfig {
        let auth_classes = vec![
            setup_oidc_auth_class(OIDC_AUTH_CLASS_1),
            setup_file_auth_class(FILE_AUTH_CLASS_1),
            setup_file_auth_class(FILE_AUTH_CLASS_2),
            setup_ldap_auth_class_with_bind_credentials_secret_class(
                LDAP_AUTH_CLASS_1,
                "secret_class",
            ),
            setup_ldap_auth_class_with_bind_credentials_secret_class(
                LDAP_AUTH_CLASS_2,
                "secret_class",
            ),
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

        // check if auth class order is preserved
        assert_eq!(
            config_properties.get(HTTP_SERVER_AUTHENTICATION_TYPE),
            Some("OAUTH2,PASSWORD".to_string()).as_ref(),
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
        assert!(
            setup_authentication_config()
                .config_files(&TrinoRole::Worker)
                .is_empty()
        );

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
            Some(format!("ldap.allow-insecure=true\nldap.group-auth-pattern=(&(uid\\=${{USER}}))\nldap.url=ldap\\://{HOST_NAME}\\:389\nldap.user-base-dn={SEARCH_BASE}\npassword-authenticator.name=ldap\n")).as_ref()
        );

        assert_eq!(
            config_files.get(&format!("{LDAP_AUTH_CLASS_2}-password-ldap-auth.properties")),
                Some(format!("ldap.allow-insecure=true\nldap.group-auth-pattern=(&(uid\\=${{USER}}))\nldap.url=ldap\\://{HOST_NAME}\\:389\nldap.user-base-dn={SEARCH_BASE}\npassword-authenticator.name=ldap\n")).as_ref()
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
                .filter(|v| v.name == FILE_AUTH_CLASS_1 || v.name == FILE_AUTH_CLASS_2)
                .count(),
            2
        );
    }

    #[test]
    fn test_trino_password_authenticator_volume_mounts() {
        // nothing for workers
        assert!(
            setup_authentication_config()
                .volume_mounts(&TrinoRole::Worker, &crate::crd::Container::Trino,)
                .is_empty()
        );
        assert!(
            setup_authentication_config()
                .volume_mounts(&TrinoRole::Worker, &crate::crd::Container::Prepare,)
                .is_empty()
        );

        // coordinator - main container
        let coordinator_main_mounts = setup_authentication_config()
            .volume_mounts(&TrinoRole::Coordinator, &crate::crd::Container::Trino);

        // we expect one user password db mount
        assert_eq!(coordinator_main_mounts.len(), 1);
        assert_eq!(coordinator_main_mounts.first().unwrap().name, "users");
        assert_eq!(
            coordinator_main_mounts.first().unwrap().mount_path,
            "/stackable/users"
        );
    }

    #[test]
    fn test_trino_password_authenticator_commands() {
        let auth_config = setup_authentication_config();
        let auth_config_with_ldap_bind = setup_authentication_config_bind_credentials();

        // nothing for workers
        assert!(
            auth_config
                .commands(&TrinoRole::Worker, &crate::crd::Container::Trino)
                .is_empty()
        );
        assert!(
            auth_config_with_ldap_bind
                .commands(&TrinoRole::Worker, &crate::crd::Container::Trino)
                .is_empty()
        );

        // we expect 0 entries because no bind credentials env export
        assert_eq!(
            auth_config
                .commands(&TrinoRole::Coordinator, &crate::crd::Container::Trino)
                .len(),
            0
        );

        // We expect 8 entries because of "set +x", "set -x" and 2x user:password bind credential env export
        assert_eq!(
            auth_config_with_ldap_bind
                .commands(&TrinoRole::Coordinator, &crate::crd::Container::Trino)
                .len(),
            8
        );
    }

    #[test]
    fn test_trino_password_authenticator_sidecar_containers() {
        let auth_config = setup_authentication_config();
        // expect one file user password db update container
        assert_eq!(auth_config.sidecar_containers.len(), 1);
    }

    /// Helper function to deserialize objects with serde. We need this 'singleton_map_recursive' thing, otherwise
    /// untagged enums will not deserialize correctly.
    fn deserialize<'de, T: stackable_operator::k8s_openapi::serde::Deserialize<'de>>(
        input: &'de str,
    ) -> T {
        let deserializer = serde_yaml::Deserializer::from_str(input);
        serde_yaml::with::singleton_map_recursive::deserialize(deserializer).unwrap()
    }
}
