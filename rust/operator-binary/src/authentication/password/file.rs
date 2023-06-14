use crate::authentication::password::{CONFIG_FILE_NAME_SUFFIX, PASSWORD_AUTHENTICATOR_NAME};

use stackable_operator::{
    builder::{ContainerBuilder, VolumeBuilder, VolumeMountBuilder},
    commons::authentication::StaticAuthenticationProvider,
    commons::product_image_selection::ResolvedProductImage,
    k8s_openapi::api::core::v1::{Container, Volume, VolumeMount},
};
use std::collections::BTreeMap;

// mounts
const PASSWORD_DB_VOLUME_NAME: &str = "users";
pub const PASSWORD_DB_VOLUME_MOUNT_PATH: &str = "/stackable/users";
pub const PASSWORD_AUTHENTICATOR_SECRET_MOUNT_PATH: &str = "/stackable/auth-secrets";
// trino properties
const PASSWORD_AUTHENTICATOR_NAME_FILE: &str = "file";
const FILE_PASSWORD_FILE: &str = "file.password-file";

#[derive(Clone, Debug)]
pub struct FileAuthenticator {
    name: String,
    file: StaticAuthenticationProvider,
}

impl FileAuthenticator {
    pub fn new(name: String, provider: StaticAuthenticationProvider) -> Self {
        Self {
            name,
            file: provider,
        }
    }

    pub fn config_file_name(&self) -> String {
        format!(
            "{name}-password-file-auth{CONFIG_FILE_NAME_SUFFIX}",
            name = self.name
        )
    }

    pub fn config_file_data(&self) -> BTreeMap<String, String> {
        let mut config_data = BTreeMap::new();
        config_data.insert(
            PASSWORD_AUTHENTICATOR_NAME.to_string(),
            PASSWORD_AUTHENTICATOR_NAME_FILE.to_string(),
        );
        config_data.insert(FILE_PASSWORD_FILE.to_string(), self.password_file_path());
        config_data
    }

    pub fn secret_volume(&self) -> Volume {
        VolumeBuilder::new(self.secret_volume_name())
            .with_secret(&self.file.user_credentials_secret.name, false)
            .build()
    }

    pub fn secret_volume_mount(&self) -> VolumeMount {
        VolumeMountBuilder::new(self.secret_volume_name(), self.secret_class_mount_path()).build()
    }

    pub fn password_db_volume() -> Volume {
        VolumeBuilder::new(PASSWORD_DB_VOLUME_NAME)
            .with_empty_dir(None::<String>, None)
            .build()
    }

    pub fn password_db_volume_mount() -> VolumeMount {
        VolumeMountBuilder::new(PASSWORD_DB_VOLUME_NAME, PASSWORD_DB_VOLUME_MOUNT_PATH).build()
    }

    fn password_file_name(&self) -> String {
        // TODO: document max volume mount size of 63 characters: (auth_class + secret_name + 1) < 63
        format!(
            "{auth_class}-{credentials}.db",
            auth_class = self.name,
            credentials = self.file.user_credentials_secret.name
        )
    }

    fn password_file_path(&self) -> String {
        format!(
            "{mount}/{file_name}",
            mount = PASSWORD_DB_VOLUME_MOUNT_PATH,
            file_name = self.password_file_name()
        )
    }

    fn secret_volume_name(&self) -> String {
        // TODO: document max volume mount size of 63 characters: (auth_class + secret_name + 1) < 63
        // auth class + secret name for uniqueness
        format!(
            "{auth_class}-{secret_name}",
            auth_class = self.name,
            secret_name = self.file.user_credentials_secret.name
        )
    }

    fn secret_class_mount_path(&self) -> String {
        format!(
            "{PASSWORD_AUTHENTICATOR_SECRET_MOUNT_PATH}/{volume_name}",
            volume_name = self.secret_volume_name()
        )
    }
}

pub fn build_password_file_update_container(
    resolved_product_image: &ResolvedProductImage,
    volume_mounts: Vec<VolumeMount>,
) -> Container {
    // unwrap is save due to the fixed name
    let mut cb_pw_file_updater =
        ContainerBuilder::new(&stackable_trino_crd::Container::PasswordFileUpdater.to_string())
            .unwrap();

    cb_pw_file_updater
        .image_from_product_image(resolved_product_image)
        .add_volume_mounts(volume_mounts)
        .command(vec!["/bin/bash".to_string(), "-c".to_string()])
        .args(vec![format!(
            r###"
echo '
#!/bin/bash

poll_interval_seconds=5

while true
do
  echo "Create user password database from secrets..."
  for secret in {stackable_auth_secret_dir}/*; do
    credentials=""
    secret_name="$(basename ${{secret}})"
    echo "Processing secret [$secret_name] ..."

    for user in ${{secret}}/*; do
      user_name=$(basename ${{user}})
      password=$(cat ${{user}})
      credentials+="$(htpasswd -nbBC 10 ${{user_name}} ${{password}})"
      credentials+=" "
    done
    
    echo "${{credentials}}" | tr " " "\n" > "{stackable_password_db_dir}/${{secret_name}}.db"
  done

  echo "All done. Next round in {poll_interval} seconds!"
  echo ""
  
  sleep {poll_interval}
done' > /tmp/build_password_db.sh && chmod +x /tmp/build_password_db.sh && /tmp/build_password_db.sh
"###,
            stackable_password_db_dir = PASSWORD_DB_VOLUME_MOUNT_PATH,
            stackable_auth_secret_dir = PASSWORD_AUTHENTICATOR_SECRET_MOUNT_PATH,
            poll_interval = 5
        )])
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use stackable_operator::commons::authentication::static_::UserCredentialsSecretRef;

    #[test]
    fn test_file_authenticator() {
        let authenticator = FileAuthenticator::new(
            "test".to_string(),
            StaticAuthenticationProvider {
                user_credentials_secret: UserCredentialsSecretRef {
                    name: "user_credentials".to_string(),
                },
            },
        );

        assert_eq!(
            authenticator
                .config_file_data()
                .get(PASSWORD_AUTHENTICATOR_NAME),
            Some(PASSWORD_AUTHENTICATOR_NAME_FILE.to_string()).as_ref()
        );

        assert_eq!(
            authenticator.config_file_data().get(FILE_PASSWORD_FILE),
            Some(authenticator.password_file_path()).as_ref()
        );
    }
}