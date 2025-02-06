use std::{
    ops::{Deref, RangeBounds},
    str::FromStr,
};

use semver::{BuildMetadata, Prerelease};
use snafu::{ResultExt as _, Snafu};

/// Represent a Trino version as a Semver
///
/// Currently, Trino uses a single number as the version.
/// Previously there were 0.x versions, but they are long gone and will not be
/// catered to.
#[derive(PartialOrd, PartialEq)]
pub struct TrinoVersion(semver::Version);

impl Deref for TrinoVersion {
    type Target = semver::Version;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<u64> for TrinoVersion {
    fn as_ref(&self) -> &u64 {
        &self.major
    }
}

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("unable to construct a 0.0.0 pre-release semver from {input:?}"))]
    ContructSemver {
        source: semver::Error,
        input: String,
    },
}

impl FromStr for TrinoVersion {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let version = match input.parse::<u64>() {
            Ok(major) => semver::Version::new(major, 0, 0),
            Err(_) => semver::Version {
                major: 0,
                minor: 0,
                patch: 0,
                pre: Prerelease::new(input).context(ContructSemverSnafu { input })?,
                build: BuildMetadata::EMPTY,
            },
        };
        Ok(Self(version))
    }
}
