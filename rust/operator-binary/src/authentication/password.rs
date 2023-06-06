use stackable_operator::commons::authentication::{
    LdapAuthenticationProvider, StaticAuthenticationProvider,
};

const AUTHENTICATOR_FILE_SUFFIX: &str = ".properties";

#[derive(Clone, Debug)]
pub struct TrinoPasswordAuthenticator {
    name: String,
    authenticator: TrinoPasswordAuthenticatorType,
}

impl TrinoPasswordAuthenticator {
    pub fn new(auth_class_name: String, authenticator: TrinoPasswordAuthenticatorType) -> Self {
        Self {
            name: auth_class_name,
            authenticator,
        }
    }

    pub fn name(&self) -> &str {
        self.name.as_ref()
    }

    pub fn file_name(&self) -> String {
        format!("{name}{AUTHENTICATOR_FILE_SUFFIX}", name = self.name)
    }

    pub fn authenticator(&self) -> &TrinoPasswordAuthenticatorType {
        &self.authenticator
    }
}

#[derive(Clone, Debug)]
pub enum TrinoPasswordAuthenticatorType {
    File(StaticAuthenticationProvider),
    Ldap(LdapAuthenticationProvider),
}
