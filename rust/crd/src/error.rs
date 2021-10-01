#[derive(Debug, thiserror::Error)]
pub enum Error {

    #[error("Pod has no hostname assignment, this is most probably a transitive failure and should be retried: [{pod}]")]
    PodWithoutHostname { pod: String },

    #[error("Pod [{pod}] is missing the following required labels: [{labels:?}]")]
    PodMissingLabels { pod: String, labels: Vec<String> },

    #[error("Got object with no name from Kubernetes, this should not happen, please open a ticket for this with the reference: [{reference}]")]
    ObjectWithoutName { reference: String },

    #[error("Kubernetes reported error: {source}")]
    KubeError {
        #[from]
        source: kube::Error,
    },

    #[error("Operator Framework reported error: {source}")]
    OperatorFrameworkError {
        #[from]
        source: stackable_operator::error::Error,
    },
}

pub type TrinoOperatorResult<T> = std::result::Result<T, Error>;
