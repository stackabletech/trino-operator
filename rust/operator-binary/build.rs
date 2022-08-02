use stackable_operator::crd::CustomResourceExt;
use stackable_trino_crd::{catalog::TrinoCatalog, TrinoCluster};

fn main() -> Result<(), stackable_operator::error::Error> {
    built::write_built_file().expect("Failed to acquire build-time information");

    TrinoCluster::write_yaml_schema("../../deploy/crd/trinocluster.crd.yaml")?;
    TrinoCatalog::write_yaml_schema("../../deploy/crd/trinocatalog.crd.yaml")?;

    Ok(())
}
