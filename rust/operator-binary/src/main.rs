mod controller;

use clap::Parser;
use futures::stream::StreamExt;
use stackable_operator::cli::Command;
use stackable_operator::{
    k8s_openapi::api::{
        apps::v1::StatefulSet,
        core::v1::{ConfigMap, Service},
    },
    kube::{
        api::ListParams,
        runtime::{controller::Context, Controller},
        CustomResourceExt,
    },
};
use stackable_regorule_crd::RegoRule;
use stackable_trino_crd::TrinoCluster;

mod built_info {
    include!(concat!(env!("OUT_DIR"), "/built.rs"));
}

#[derive(Parser)]
#[clap(about = built_info::PKG_DESCRIPTION, author = stackable_operator::cli::AUTHOR)]
struct Opts {
    #[clap(subcommand)]
    cmd: Command,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    stackable_operator::logging::initialize_logging("TRINO_OPERATOR_LOG");

    let opts = Opts::parse();
    match opts.cmd {
        Command::Crd => println!("{}", serde_yaml::to_string(&TrinoCluster::crd())?,),
        Command::Run(product_config) => {
            stackable_operator::utils::print_startup_string(
                built_info::PKG_DESCRIPTION,
                built_info::PKG_VERSION,
                built_info::GIT_VERSION,
                built_info::TARGET,
                built_info::BUILT_TIME_UTC,
                built_info::RUSTC_VERSION,
            );
            let product_config = product_config.product_config.load(&[
                "deploy/config-spec/properties.yaml",
                "/etc/stackable/trino-operator/config-spec/properties.yaml",
            ])?;

            let client =
                stackable_operator::client::create_client(Some("trino.stackable.tech".to_string()))
                    .await?;

            Controller::new(client.get_all_api::<TrinoCluster>(), ListParams::default())
                .owns(client.get_all_api::<Service>(), ListParams::default())
                .owns(client.get_all_api::<StatefulSet>(), ListParams::default())
                .owns(client.get_all_api::<ConfigMap>(), ListParams::default())
                .owns(client.get_all_api::<RegoRule>(), ListParams::default())
                .shutdown_on_signal()
                .run(
                    controller::reconcile_trino,
                    controller::error_policy,
                    Context::new(controller::Ctx {
                        client: client.clone(),
                        product_config,
                    }),
                )
                .for_each(|res| async {
                    match res {
                        Ok((obj, _)) => tracing::info!(object = %obj, "Reconciled object"),
                        Err(err) => {
                            tracing::error!(
                                error = &err as &dyn std::error::Error,
                                "Failed to reconcile object",
                            )
                        }
                    }
                })
                .await;
        }
    }

    Ok(())
}
