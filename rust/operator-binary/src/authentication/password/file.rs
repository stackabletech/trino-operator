use crate::authentication::password::PASSWORD_AUTHENTICATOR_NAME;
use crate::controller::STACKABLE_LOG_DIR;

use stackable_operator::{
    builder::{
        resources::ResourceRequirementsBuilder, ContainerBuilder, VolumeBuilder, VolumeMountBuilder,
    },
    commons::authentication::StaticAuthenticationProvider,
    commons::product_image_selection::ResolvedProductImage,
    k8s_openapi::api::core::v1::{Container, Volume, VolumeMount},
    product_logging::{self, spec::AutomaticContainerLogConfig},
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

    /// Return the name of the authenticator config file to register with Trino
    pub fn config_file_name(&self) -> String {
        format!("{name}-password-file-auth.properties", name = self.name)
    }

    /// Return the content of the authenticator config file to register with Trino
    pub fn config_file_data(&self) -> BTreeMap<String, String> {
        let mut config_data = BTreeMap::new();
        config_data.insert(
            PASSWORD_AUTHENTICATOR_NAME.to_string(),
            PASSWORD_AUTHENTICATOR_NAME_FILE.to_string(),
        );
        config_data.insert(FILE_PASSWORD_FILE.to_string(), self.password_file_path());
        config_data
    }

    /// Build the volume for the user secret
    pub fn secret_volume(&self) -> Volume {
        VolumeBuilder::new(self.secret_volume_name())
            .with_secret(&self.file.user_credentials_secret.name, false)
            .build()
    }

    /// Build the volume mount for the user secret
    pub fn secret_volume_mount(&self) -> VolumeMount {
        VolumeMountBuilder::new(self.secret_volume_name(), self.secret_class_mount_path()).build()
    }

    /// Build the volume for the user password db
    pub fn password_db_volume() -> Volume {
        VolumeBuilder::new(PASSWORD_DB_VOLUME_NAME)
            .with_empty_dir(None::<String>, None)
            .build()
    }

    /// Build the volume mount for the user password db
    pub fn password_db_volume_mount() -> VolumeMount {
        VolumeMountBuilder::new(PASSWORD_DB_VOLUME_NAME, PASSWORD_DB_VOLUME_MOUNT_PATH).build()
    }

    fn password_file_name(&self) -> String {
        format!("{auth_class}.db", auth_class = self.name,)
    }

    fn password_file_path(&self) -> String {
        format!(
            "{mount}/{file_name}",
            mount = PASSWORD_DB_VOLUME_MOUNT_PATH,
            file_name = self.password_file_name()
        )
    }

    fn secret_volume_name(&self) -> String {
        self.name.to_string()
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
    let mut cb_pw_file_updater =
        ContainerBuilder::new(&stackable_trino_crd::Container::PasswordFileUpdater.to_string())
            .expect(
                "Invalid container name. This should not happen, as the container name is fixed",
            );

    let mut commands = vec![];

    commands.push(product_logging::framework::capture_shell_output(
        STACKABLE_LOG_DIR,
        &stackable_trino_crd::Container::PasswordFileUpdater.to_string(),
        // we do not access any of the crd config options for this and just log it to file
        &AutomaticContainerLogConfig::default(),
    ));

    commands.push(format!(
        r###"
echo '
#!/bin/bash

build_user_dbs() {{
  echo "[$(date --utc +%FT%T.%3NZ)] Detected changes. Start recreating user password databases from secrets..."
  for secret in {stackable_auth_secret_dir}/*;
  do
    credentials=""
    secret_name="$(basename ${{secret}})"
    echo "[$(date --utc +%FT%T.%3NZ)] Processing secret [$secret_name] ..."

    for user in ${{secret}}/*; do
      user_name=$(basename ${{user}})
      password=$(cat ${{user}})
      credentials+="$(htpasswd -nbBC 12 ${{user_name}} ${{password}})"
      credentials+=" "
    done

    echo "${{credentials}}" | tr " " "\n" > "{stackable_password_db_dir}/${{secret_name}}.db"
  done
}}

# Once initial run after start / restart
build_user_dbs

while inotifywait -s -r -e create -e delete -e modify {stackable_auth_secret_dir};
do
  build_user_dbs
  echo "[$(date --utc +%FT%T.%3NZ)] All databases recreated. Waiting for changes..."
done' > /tmp/build_password_db.sh && chmod +x /tmp/build_password_db.sh && /tmp/build_password_db.sh
"###,
        stackable_password_db_dir = PASSWORD_DB_VOLUME_MOUNT_PATH,
        stackable_auth_secret_dir = PASSWORD_AUTHENTICATOR_SECRET_MOUNT_PATH,
    ));

    cb_pw_file_updater
        .image_from_product_image(resolved_product_image)
        // calculated mounts
        .add_volume_mounts(volume_mounts)
        // fixed
        .add_volume_mount("log", STACKABLE_LOG_DIR)
        .resources(
            ResourceRequirementsBuilder::new()
                .with_cpu_request("100m")
                .with_cpu_limit("200m")
                .with_memory_request("32Mi")
                .with_memory_limit("32Mi")
                .build(),
        )
        .command(vec![
            "/bin/bash".to_string(),
            "-x".to_string(),
            "-euo".to_string(),
            "pipefail".to_string(),
            "-c".to_string(),
        ])
        .args(vec![commands.join(" && ")])
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use stackable_operator::commons::authentication::static_::UserCredentialsSecretRef;

    const AUTH_CLASS_NAME: &str = "test-auth";

    #[test]
    fn test_file_authenticator() {
        let authenticator = FileAuthenticator::new(
            AUTH_CLASS_NAME.to_string(),
            StaticAuthenticationProvider {
                user_credentials_secret: UserCredentialsSecretRef {
                    name: "user_credentials".to_string(),
                },
            },
        );

        let file_name = authenticator.config_file_name();
        assert_eq!(
            file_name,
            format!("{AUTH_CLASS_NAME}-password-file-auth.properties",)
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
