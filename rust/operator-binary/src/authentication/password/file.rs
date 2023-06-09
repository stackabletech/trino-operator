use crate::authentication::{
    password::{
        PasswordAuthenticator, PASSWORD_AUTHENTICATOR_NAME, PASSWORD_CONFIG_FILE_NAME_SUFFIX,
    },
    Result,
};

use snafu::Snafu;
use stackable_operator::commons::authentication::StaticAuthenticationProvider;
use std::collections::BTreeMap;

// file names
pub(crate) const FILE_AUTHENTICATOR_PROPERTIES_NAME: &str = "file-authenticator";
const FILE_PASSWORD_DB_NAME: &str = "password.db";
// trino properties
const PASSWORD_AUTHENTICATOR_NAME_FILE: &str = "file";
const FILE_PASSWORD_FILE: &str = "file.password-file";
// mounts
const PASSWORD_DB_VOLUME_MOUNT_PATH: &str = "/stackable/users";

#[derive(Snafu, Debug)]
pub enum Error {}

#[derive(Clone, Debug)]
pub struct FileAuthenticator {
    provider: StaticAuthenticationProvider,
}

impl FileAuthenticator {
    pub fn new(provider: StaticAuthenticationProvider) -> Self {
        Self { provider }
    }

    pub fn password_db_file_name() -> String {
        FILE_PASSWORD_DB_NAME.to_string()
    }

    pub fn password_db_file_path() -> String {
        format!(
            "{PASSWORD_DB_VOLUME_MOUNT_PATH}/{name}",
            name = Self::password_db_file_name()
        )
    }

    pub fn config_file_properties(&self) -> BTreeMap<String, String> {
        let mut config_data = BTreeMap::new();
        config_data.insert(
            PASSWORD_AUTHENTICATOR_NAME.to_string(),
            PASSWORD_AUTHENTICATOR_NAME_FILE.to_string(),
        );
        config_data.insert(
            FILE_PASSWORD_FILE.to_string(),
            Self::password_db_file_path(),
        );
        config_data
    }
}

impl PasswordAuthenticator for FileAuthenticator {
    fn name(&self) -> &str {
        FILE_AUTHENTICATOR_PROPERTIES_NAME
    }

    fn config_file_content(&self) -> Result<BTreeMap<String, String>> {
        let mut config_data = BTreeMap::new();
        config_data.insert(
            PASSWORD_AUTHENTICATOR_NAME.to_string(),
            PASSWORD_AUTHENTICATOR_NAME_FILE.to_string(),
        );
        config_data.insert(
            FILE_PASSWORD_FILE.to_string(),
            Self::password_db_file_path(),
        );
        Ok(config_data)
    }

    fn config_file_name(&self) -> String {
        format!("{FILE_AUTHENTICATOR_PROPERTIES_NAME}{PASSWORD_CONFIG_FILE_NAME_SUFFIX}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stackable_operator::commons::authentication::static_::UserCredentialsSecretRef;

    #[test]
    fn test_file_authenticator() {
        let authenticator = FileAuthenticator::new(StaticAuthenticationProvider {
            user_credentials_secret: UserCredentialsSecretRef {
                name: "user_credentials".to_string(),
            },
        });

        assert_eq!(
            authenticator
                .config_file_properties()
                .get(PASSWORD_AUTHENTICATOR_NAME),
            Some(PASSWORD_AUTHENTICATOR_NAME_FILE.to_string()).as_ref()
        );

        assert_eq!(
            authenticator
                .config_file_properties()
                .get(FILE_PASSWORD_FILE),
            Some(FileAuthenticator::password_db_file_path()).as_ref()
        );
    }
}
