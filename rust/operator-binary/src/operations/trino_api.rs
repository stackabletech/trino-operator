//! HTTP client for the Trino worker graceful shutdown REST API.
//!
//! Each Trino worker exposes `/v1/info/state` which returns and accepts one of
//! three states: `ACTIVE`, `SHUTTING_DOWN`, or `INACTIVE`.
//!
//! See <https://trino.io/docs/current/admin/graceful-shutdown.html>.

use std::fmt;

use snafu::{ResultExt, Snafu};

/// States reported by Trino's `/v1/info/state` endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrinoWorkerState {
    /// Worker is running and accepting new tasks.
    Active,
    /// Worker is draining — no new tasks are scheduled, existing tasks run to completion.
    ShuttingDown,
    /// Worker has finished draining and is ready to be terminated.
    Inactive,
}

impl fmt::Display for TrinoWorkerState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Active => write!(f, "ACTIVE"),
            Self::ShuttingDown => write!(f, "SHUTTING_DOWN"),
            Self::Inactive => write!(f, "INACTIVE"),
        }
    }
}

/// Errors from Trino worker API operations.
#[derive(Debug, Snafu)]
pub enum Error {
    /// Failed to build the HTTP client.
    #[snafu(display("failed to build Trino HTTP client"))]
    BuildClient { source: reqwest::Error },

    /// Failed to query the worker state.
    #[snafu(display("failed to GET /v1/info/state from {url}"))]
    GetState { source: reqwest::Error, url: String },

    /// Failed to initiate graceful shutdown on the worker.
    #[snafu(display("failed to PUT /v1/info/state on {url}"))]
    PutState { source: reqwest::Error, url: String },

    /// The GET response returned a non-success status code.
    #[snafu(display("GET /v1/info/state returned {status} from {url}"))]
    GetStateStatus {
        status: reqwest::StatusCode,
        url: String,
    },

    /// The PUT response returned a non-success status code.
    #[snafu(display("PUT /v1/info/state returned {status} from {url}"))]
    PutStateStatus {
        status: reqwest::StatusCode,
        url: String,
    },

    /// The state string returned by Trino was not recognized.
    #[snafu(display("unrecognized Trino worker state: {state:?}"))]
    UnrecognizedState { state: String },
}

/// HTTP client for a single Trino worker's `/v1/info/state` endpoint.
pub struct TrinoWorkerClient {
    client: reqwest::Client,
    state_url: String,
}

impl TrinoWorkerClient {
    /// Create a new client targeting a specific worker.
    ///
    /// # Parameters
    ///
    /// - `base_url`: The base URL of the worker, e.g. `https://host:8443`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::BuildClient`] if the reqwest client cannot be constructed.
    pub fn new(base_url: &str) -> Result<Self, Error> {
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .context(BuildClientSnafu)?;

        Ok(Self {
            client,
            state_url: format!("{base_url}/v1/info/state"),
        })
    }

    /// Query the current state of the worker.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP request fails, returns a non-success status,
    /// or the response body contains an unrecognized state string.
    pub async fn get_state(&self) -> Result<TrinoWorkerState, Error> {
        let response = self
            .client
            .get(&self.state_url)
            .header("X-Trino-User", "graceful-shutdown-user")
            .header("X-Trino-Source", "Stackable data platform")
            .send()
            .await
            .context(GetStateSnafu {
                url: &self.state_url,
            })?;

        let status = response.status();
        if !status.is_success() {
            return GetStateStatusSnafu {
                status,
                url: &self.state_url,
            }
            .fail();
        }

        let body: String = response.text().await.context(GetStateSnafu {
            url: &self.state_url,
        })?;

        parse_state(&body)
    }

    /// Initiate graceful shutdown on the worker by setting its state to `SHUTTING_DOWN`.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP request fails or returns a non-success status.
    pub async fn initiate_shutdown(&self) -> Result<(), Error> {
        let response = self
            .client
            .put(&self.state_url)
            .header("Content-Type", "application/json")
            .header("X-Trino-User", "graceful-shutdown-user")
            .header("X-Trino-Source", "Stackable data platform")
            .body("\"SHUTTING_DOWN\"")
            .send()
            .await
            .context(PutStateSnafu {
                url: &self.state_url,
            })?;

        let status = response.status();
        if !status.is_success() {
            return PutStateStatusSnafu {
                status,
                url: &self.state_url,
            }
            .fail();
        }

        Ok(())
    }
}

/// Parse a Trino worker state from the JSON response body.
///
/// The response is a JSON-encoded string, e.g. `"ACTIVE"` (with quotes).
fn parse_state(body: &str) -> Result<TrinoWorkerState, Error> {
    // The response is a JSON string — strip surrounding quotes.
    let trimmed = body.trim().trim_matches('"');
    match trimmed {
        "ACTIVE" => Ok(TrinoWorkerState::Active),
        "SHUTTING_DOWN" => Ok(TrinoWorkerState::ShuttingDown),
        "INACTIVE" => Ok(TrinoWorkerState::Inactive),
        other => UnrecognizedStateSnafu {
            state: other.to_string(),
        }
        .fail(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_active() {
        assert_eq!(parse_state("\"ACTIVE\"").unwrap(), TrinoWorkerState::Active);
    }

    #[test]
    fn parse_shutting_down() {
        assert_eq!(
            parse_state("\"SHUTTING_DOWN\"").unwrap(),
            TrinoWorkerState::ShuttingDown
        );
    }

    #[test]
    fn parse_inactive() {
        assert_eq!(
            parse_state("\"INACTIVE\"").unwrap(),
            TrinoWorkerState::Inactive
        );
    }

    #[test]
    fn parse_with_whitespace() {
        assert_eq!(
            parse_state("  \"ACTIVE\"  \n").unwrap(),
            TrinoWorkerState::Active
        );
    }

    #[test]
    fn parse_unknown_state_errors() {
        assert!(parse_state("\"UNKNOWN\"").is_err());
    }
}
