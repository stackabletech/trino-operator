use stackable_operator::crd::CustomResourceExt;
use stackable_trino_crd::TrinoCluster;

fn main() -> Result<(), stackable_operator::error::Error> {
    built::write_built_file().expect("Failed to acquire build-time information");

    TrinoCluster::write_yaml_schema("../../deploy/crd/trinocluster.crd.yaml")?;

    Ok(())
}
