//! Java-properties writer.
//!
//! Reproduces the escape rules required for Trino's `.properties` files. Pinned
//! by the kuttl ConfigMap snapshot at
//! `tests/templates/kuttl/smoke/14-assert.yaml.j2`.
// TODO(@maltesander): should be moved to a common crate in operator-rs.

use std::collections::BTreeMap;

use snafu::{ResultExt, Snafu};

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("failed to write properties output"))]
    Format { source: std::fmt::Error },
}

/// Serialize `props` as a Java-properties string, sorted by key.
///
/// Keys and values are escaped per <https://docs.oracle.com/javase/8/docs/api/java/util/Properties.html>:
/// `:`, `=`, `#`, `!`, `\\`, leading whitespace, and ` ` (space).
pub fn to_java_properties_string(props: &BTreeMap<String, String>) -> Result<String, Error> {
    use std::fmt::Write;
    let mut out = String::new();
    for (k, v) in props {
        writeln!(out, "{}={}", escape_key(k), escape_value(v)).context(FormatSnafu)?;
    }
    Ok(out)
}

fn escape_key(key: &str) -> String {
    let mut out = String::with_capacity(key.len());
    for c in key.chars() {
        match c {
            '\\' | ':' | '=' | '#' | '!' | ' ' => {
                out.push('\\');
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    out
}

fn escape_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut at_start = true;
    for c in value.chars() {
        match c {
            '\\' | ':' | '=' | '#' | '!' => {
                out.push('\\');
                out.push(c);
            }
            ' ' if at_start => {
                out.push('\\');
                out.push(' ');
            }
            _ => out.push(c),
        }
        if c != ' ' {
            at_start = false;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn render(pairs: &[(&str, &str)]) -> String {
        let props: BTreeMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        to_java_properties_string(&props).unwrap()
    }

    #[test]
    fn empty_map_renders_empty_string() {
        let props: BTreeMap<String, String> = BTreeMap::new();
        assert_eq!(to_java_properties_string(&props).unwrap(), "");
    }

    #[test]
    fn keys_are_sorted_alphabetically() {
        assert_eq!(render(&[("b", "2"), ("a", "1")]), "a=1\nb=2\n");
    }

    #[test]
    fn colon_in_value_is_escaped() {
        // From smoke snapshot:
        //   internal-communication.shared-secret=${ENV\:INTERNAL_SECRET}
        assert_eq!(
            render(&[(
                "internal-communication.shared-secret",
                "${ENV:INTERNAL_SECRET}"
            )]),
            "internal-communication.shared-secret=${ENV\\:INTERNAL_SECRET}\n"
        );
    }

    #[test]
    fn colon_in_url_value_is_escaped() {
        // From smoke snapshot:
        //   discovery.uri=https\://trino-coordinator-default-0...:8443
        assert_eq!(
            render(&[("discovery.uri", "https://trino-coordinator.svc:8443")]),
            "discovery.uri=https\\://trino-coordinator.svc\\:8443\n"
        );
    }

    #[test]
    fn equals_in_value_is_escaped() {
        assert_eq!(render(&[("k", "a=b")]), "k=a\\=b\n");
    }

    #[test]
    fn backslash_in_value_is_escaped() {
        assert_eq!(render(&[("k", "a\\b")]), "k=a\\\\b\n");
    }

    #[test]
    fn leading_space_in_value_is_escaped() {
        assert_eq!(render(&[("k", " v")]), "k=\\ v\n");
    }

    #[test]
    fn non_leading_space_in_value_is_not_escaped() {
        assert_eq!(render(&[("k", "a b")]), "k=a b\n");
    }

    #[test]
    fn space_in_key_is_escaped() {
        assert_eq!(render(&[("a b", "1")]), "a\\ b=1\n");
    }

    #[test]
    fn hash_and_bang_in_value_are_escaped() {
        assert_eq!(render(&[("k", "#comment")]), "k=\\#comment\n");
        assert_eq!(render(&[("k", "!bang")]), "k=\\!bang\n");
    }
}
