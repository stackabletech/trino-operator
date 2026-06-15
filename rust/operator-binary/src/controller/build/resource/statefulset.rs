//! Builds the per-rolegroup [`StatefulSet`] that runs a Trino role group.

use std::{collections::BTreeMap, convert::Infallible, str::FromStr};

use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::{
    builder::{
        meta::ObjectMetaBuilder,
        pod::{
            PodBuilder,
            container::ContainerBuilder,
            resources::ResourceRequirementsBuilder,
            security::PodSecurityContextBuilder,
            volume::{SecretFormat, SecretOperatorVolumeSourceBuilder, VolumeBuilder},
        },
    },
    commons::{
        product_image_selection::ResolvedProductImage,
        secret_class::SecretClassVolumeProvisionParts,
    },
    constants::RESTART_CONTROLLER_ENABLED_LABEL,
    k8s_openapi::{
        DeepMerge,
        api::{
            apps::v1::{StatefulSet, StatefulSetSpec},
            core::v1::{
                ConfigMapVolumeSource, ContainerPort, EnvVar, EnvVarSource, ExecAction,
                HTTPGetAction, Probe, SecretKeySelector, Volume,
            },
        },
        apimachinery::pkg::{apis::meta::v1::LabelSelector, util::intstr::IntOrString},
    },
    kvp::{Annotation, Annotations, Labels},
    product_logging,
    shared::time::Duration,
    v2::{
        builder::pod::container::EnvVarSet,
        product_logging::framework::{ValidatedContainerLogConfigChoice, vector_container},
        types::kubernetes::{ContainerName, VolumeName},
    },
};

use crate::{
    authentication::TrinoAuthenticationConfig,
    authorization::opa::{OPA_TLS_VOLUME_NAME, TrinoOpaConfig},
    catalog::config::CatalogConfig,
    command,
    config::{client_protocol, fault_tolerant_execution},
    controller::{
        ValidatedCluster, ValidatedTrinoConfig, build,
        build::resource::listener::{
            LISTENER_VOLUME_DIR, LISTENER_VOLUME_NAME, build_group_listener_pvc,
            group_listener_name, secret_volume_listener_scope,
        },
    },
    crd::{
        APP_NAME, CONFIG_DIR_NAME, Container, ENV_INTERNAL_SECRET, ENV_SPOOLING_SECRET, HTTP_PORT,
        HTTP_PORT_NAME, HTTPS_PORT, HTTPS_PORT_NAME, MAX_TRINO_LOG_FILES_SIZE, METRICS_PORT,
        METRICS_PORT_NAME, RW_CONFIG_DIR_NAME, STACKABLE_CLIENT_TLS_DIR,
        STACKABLE_INTERNAL_TLS_DIR, STACKABLE_MOUNT_INTERNAL_TLS_DIR,
        STACKABLE_MOUNT_SERVER_TLS_DIR, STACKABLE_SERVER_TLS_DIR, STACKABLE_TLS_STORE_PASSWORD,
        TrinoRole, v1alpha1,
    },
    trino_controller::{
        MAX_PREPARE_LOG_FILE_SIZE, STACKABLE_LOG_CONFIG_DIR, STACKABLE_LOG_DIR,
        build_recommended_labels, shared_internal_secret_name, shared_spooling_secret_name,
    },
};

stackable_operator::constant!(VECTOR_CONTAINER_NAME: ContainerName = "vector");
// The Vector agent reads its `vector.yaml` from the rolegroup ConfigMap (mounted as the "config"
// volume) and writes its state under the shared "log" volume.
stackable_operator::constant!(VECTOR_LOG_CONFIG_VOLUME_NAME: VolumeName = "config");
stackable_operator::constant!(VECTOR_LOG_VOLUME_NAME: VolumeName = "log");

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("missing secret lifetime"))]
    MissingSecretLifetime,

    #[snafu(display("object is missing metadata to build owner reference"))]
    ObjectMissingMetadataForOwnerRef {
        source: stackable_operator::builder::meta::Error,
    },

    #[snafu(display("internal operator failure: {source}"))]
    InternalOperatorFailure { source: crate::crd::Error },

    #[snafu(display("illegal container name: [{container_name}]"))]
    IllegalContainerName {
        source: stackable_operator::builder::pod::container::Error,
        container_name: String,
    },

    #[snafu(display("failed to configure graceful shutdown"))]
    GracefulShutdown {
        source: build::graceful_shutdown::Error,
    },

    #[snafu(display("failed to build Labels"))]
    LabelBuild {
        source: stackable_operator::kvp::LabelError,
    },

    #[snafu(display("failed to build Annotation"))]
    AnnotationBuild {
        source: stackable_operator::kvp::KeyValuePairError<Infallible>,
    },

    #[snafu(display("failed to build Metadata"))]
    MetadataBuild {
        source: stackable_operator::builder::meta::Error,
    },

    #[snafu(display("failed to build TLS certificate SecretClass Volume"))]
    TlsCertSecretClassVolumeBuild {
        source: stackable_operator::builder::pod::volume::SecretOperatorVolumeSourceBuilderError,
    },

    #[snafu(display("failed to add needed volume"))]
    AddVolume {
        source: stackable_operator::builder::pod::Error,
    },

    #[snafu(display("failed to add needed volumeMount"))]
    AddVolumeMount {
        source: stackable_operator::builder::pod::container::Error,
    },

    #[snafu(display("invalid Trino authentication"))]
    InvalidAuthenticationConfig {
        source: crate::authentication::Error,
    },

    #[snafu(display("failed to configure listener"))]
    ListenerConfiguration {
        source: build::resource::listener::Error,
    },
}

type Result<T, E = Error> = std::result::Result<T, E>;

/// The rolegroup [`StatefulSet`] runs the rolegroup, as configured by the administrator.
///
/// The [`Pod`](`stackable_operator::k8s_openapi::api::core::v1::Pod`)s are accessible through the
/// corresponding [`stackable_operator::k8s_openapi::api::core::v1::Service`] (from
/// [`build_rolegroup_headless_service`](super::service::build_rolegroup_headless_service)).
#[allow(clippy::too_many_arguments)]
pub fn build_rolegroup_statefulset(
    trino: &v1alpha1::TrinoCluster,
    cluster: &ValidatedCluster,
    trino_role: &TrinoRole,
    resolved_product_image: &ResolvedProductImage,
    role_group_name: &str,
    env_overrides: &EnvVarSet,
    merged_config: &ValidatedTrinoConfig,
    trino_authentication_config: &TrinoAuthenticationConfig,
    catalogs: &[CatalogConfig],
    sa_name: &str,
    resolved_fte_config: &Option<fault_tolerant_execution::ResolvedFaultTolerantExecutionConfig>,
    resolved_spooling_config: &Option<client_protocol::ResolvedClientProtocolConfig>,
    trino_opa_config: &Option<TrinoOpaConfig>,
) -> Result<StatefulSet> {
    let role = trino
        .role(trino_role)
        .context(InternalOperatorFailureSnafu)?;
    let rolegroup = trino
        .rolegroup(trino_role, role_group_name)
        .context(InternalOperatorFailureSnafu)?;

    let role_name = trino_role.to_string();
    let resource_names = cluster.resource_names(trino_role, role_group_name);
    let config_map_name = resource_names.role_group_config_map().to_string();

    let mut pod_builder = PodBuilder::new();

    let prepare_container_name = Container::Prepare.to_string();
    let mut cb_prepare = ContainerBuilder::new(&prepare_container_name).with_context(|_| {
        IllegalContainerNameSnafu {
            container_name: prepare_container_name.clone(),
        }
    })?;

    let trino_container_name = Container::Trino.to_string();
    let mut cb_trino = ContainerBuilder::new(&trino_container_name).with_context(|_| {
        IllegalContainerNameSnafu {
            container_name: trino_container_name.clone(),
        }
    })?;

    // additional authentication env vars
    let mut env = trino_authentication_config.env_vars(trino_role, &Container::Trino);

    let internal_secret_name = shared_internal_secret_name(trino);
    env.push(env_var_from_secret(
        &internal_secret_name,
        None,
        ENV_INTERNAL_SECRET,
    ));

    let spooling_secret_name = shared_spooling_secret_name(trino);
    env.push(env_var_from_secret(
        &spooling_secret_name,
        None,
        ENV_SPOOLING_SECRET,
    ));

    trino_authentication_config
        .add_authentication_pod_and_volume_config(
            trino_role,
            &mut pod_builder,
            &mut cb_prepare,
            &mut cb_trino,
        )
        .context(InvalidAuthenticationConfigSnafu)?;
    build::graceful_shutdown::add_graceful_shutdown_config(
        cluster,
        trino_role,
        merged_config,
        &mut pod_builder,
        &mut cb_trino,
    )
    .context(GracefulShutdownSnafu)?;

    // Add the needed stuff for catalogs
    env.extend(
        catalogs
            .iter()
            .flat_map(|catalog| &catalog.env_bindings)
            .cloned(),
    );

    // Needed by the `containerdebug` process to log it's tracing information to.
    // This process runs in the background of the `trino` container.
    // See command::container_trino_args() for how it's called.
    env.push(EnvVar {
        name: "CONTAINERDEBUG_LOG_DIRECTORY".into(),
        value: Some(format!("{STACKABLE_LOG_DIR}/containerdebug")),
        ..EnvVar::default()
    });

    // Finally add the user defined envOverrides properties.
    env.extend(env_overrides.clone());

    let requested_secret_lifetime = merged_config
        .requested_secret_lifetime
        .context(MissingSecretLifetimeSnafu)?;

    // add volume mounts depending on the client tls, internal tls, catalogs and authentication
    tls_volume_mounts(
        trino,
        trino_role,
        &mut pod_builder,
        &mut cb_prepare,
        &mut cb_trino,
        catalogs,
        &requested_secret_lifetime,
        resolved_fte_config,
        resolved_spooling_config,
        trino_opa_config,
    )?;

    let mut prepare_args = vec![];
    if let ValidatedContainerLogConfigChoice::Automatic(log_config) =
        &merged_config.logging.prepare_container
    {
        prepare_args.push(product_logging::framework::capture_shell_output(
            STACKABLE_LOG_DIR,
            &prepare_container_name,
            log_config,
        ));
    }

    prepare_args.extend(command::container_prepare_args(
        trino,
        catalogs,
        merged_config,
        resolved_fte_config,
        resolved_spooling_config,
    ));

    prepare_args
        .extend(trino_authentication_config.commands(&TrinoRole::Coordinator, &Container::Prepare));

    // Add OPA TLS certificate to truststore if configured
    if let Some(tls_mount_path) = trino_opa_config
        .as_ref()
        .and_then(|opa_config| opa_config.tls_mount_path())
    {
        prepare_args.extend(command::add_cert_to_truststore(
            format!("{}/ca.crt", tls_mount_path).as_str(),
            STACKABLE_CLIENT_TLS_DIR,
        ));
    }

    let container_prepare = cb_prepare
        .image_from_product_image(resolved_product_image)
        .command(vec![
            "/bin/bash".to_string(),
            "-x".to_string(),
            "-euo".to_string(),
            "pipefail".to_string(),
            "-c".to_string(),
        ])
        .args(vec![prepare_args.join("\n")])
        .add_volume_mount("rwconfig", RW_CONFIG_DIR_NAME)
        .context(AddVolumeMountSnafu)?
        .add_volume_mount("log-config", STACKABLE_LOG_CONFIG_DIR)
        .context(AddVolumeMountSnafu)?
        .add_volume_mount("log", STACKABLE_LOG_DIR)
        .context(AddVolumeMountSnafu)?
        .resources(
            ResourceRequirementsBuilder::new()
                .with_cpu_request("500m")
                .with_cpu_limit("2000m")
                .with_memory_request("4Gi")
                .with_memory_limit("4Gi")
                .build(),
        )
        .build();

    let mut persistent_volume_claims = vec![];
    // Add listener
    if let Some(group_listener_name) = group_listener_name(trino, trino_role) {
        cb_trino
            .add_volume_mount(LISTENER_VOLUME_NAME, LISTENER_VOLUME_DIR)
            .context(AddVolumeMountSnafu)?;

        // Used for PVC templates that cannot be modified once they are deployed
        let unversioned_recommended_labels = Labels::recommended(&build_recommended_labels(
            trino,
            // A version value is required, and we do want to use the "recommended" format for the other desired labels
            "none",
            &role_name,
            role_group_name,
        ))
        .context(LabelBuildSnafu)?;

        persistent_volume_claims.push(
            build_group_listener_pvc(&group_listener_name, &unversioned_recommended_labels)
                .context(ListenerConfigurationSnafu)?,
        );
    }

    let container_trino = cb_trino
        .image_from_product_image(resolved_product_image)
        .command(vec![
            "/bin/bash".to_string(),
            "-x".to_string(),
            "-euo".to_string(),
            "pipefail".to_string(),
            "-c".to_string(),
        ])
        .args(vec![
            command::container_trino_args(trino_authentication_config, catalogs).join("\n"),
        ])
        .add_env_vars(env)
        .add_volume_mount("config", CONFIG_DIR_NAME)
        .context(AddVolumeMountSnafu)?
        .add_volume_mount("rwconfig", RW_CONFIG_DIR_NAME)
        .context(AddVolumeMountSnafu)?
        .add_volume_mount("catalog", format!("{}/catalog", CONFIG_DIR_NAME))
        .context(AddVolumeMountSnafu)?
        .add_volume_mount("log", STACKABLE_LOG_DIR)
        .context(AddVolumeMountSnafu)?
        .add_container_ports(container_ports(cluster))
        .resources(merged_config.resources.clone().into())
        // The probes are set on coordinators and workers
        .startup_probe(startup_probe(cluster))
        .readiness_probe(readiness_probe(cluster))
        .liveness_probe(liveness_probe(cluster))
        .build();

    // add trino container first to better default into that container (e.g. instead of vector)
    pod_builder.add_container(container_trino);

    // add password-update container if required
    trino_authentication_config.add_authentication_containers(trino_role, &mut pod_builder);

    // The log-config volume mounts either the rolegroup ConfigMap (which carries the automatic
    // `log.properties`) or a user-provided custom ConfigMap, depending on the validated choice.
    let log_config_volume_config_map = match &merged_config.logging.trino_container {
        ValidatedContainerLogConfigChoice::Custom(config_map) => config_map.to_string(),
        ValidatedContainerLogConfigChoice::Automatic(_) => config_map_name.clone(),
    };
    pod_builder
        .add_volume(Volume {
            name: "log-config".to_string(),
            config_map: Some(ConfigMapVolumeSource {
                name: log_config_volume_config_map,
                ..ConfigMapVolumeSource::default()
            }),
            ..Volume::default()
        })
        .context(AddVolumeSnafu)?;

    if let Some(vector_log_config) = &merged_config.logging.vector_container {
        pod_builder.add_container(vector_container(
            &VECTOR_CONTAINER_NAME,
            resolved_product_image,
            vector_log_config,
            &resource_names,
            &VECTOR_LOG_CONFIG_VOLUME_NAME,
            &VECTOR_LOG_VOLUME_NAME,
            EnvVarSet::new(),
        ));
    }

    let metadata = ObjectMetaBuilder::new()
        .with_recommended_labels(&build_recommended_labels(
            trino,
            &resolved_product_image.app_version_label_value,
            &role_name,
            role_group_name,
        ))
        .context(MetadataBuildSnafu)?
        .with_annotation(
            // This is actually used by some kuttl tests (as they don't specify the container explicitly)
            Annotation::try_from(("kubectl.kubernetes.io/default-container", "trino"))
                .context(AnnotationBuildSnafu)?,
        )
        .build();

    pod_builder
        .metadata(metadata)
        .image_pull_secrets_from_product_image(resolved_product_image)
        .affinity(&merged_config.affinity)
        .add_init_container(container_prepare)
        .add_volume(Volume {
            name: "config".to_string(),
            config_map: Some(ConfigMapVolumeSource {
                name: config_map_name.clone(),
                ..ConfigMapVolumeSource::default()
            }),
            ..Volume::default()
        })
        .context(AddVolumeSnafu)?
        .add_empty_dir_volume("rwconfig", None)
        .context(AddVolumeSnafu)?
        .add_volume(Volume {
            name: "catalog".to_string(),
            config_map: Some(ConfigMapVolumeSource {
                name: format!("{config_map_name}-catalog"),
                ..ConfigMapVolumeSource::default()
            }),
            ..Volume::default()
        })
        .context(AddVolumeSnafu)?
        .add_empty_dir_volume(
            "log",
            Some(product_logging::framework::calculate_log_volume_size_limit(
                &[MAX_TRINO_LOG_FILES_SIZE, MAX_PREPARE_LOG_FILE_SIZE],
            )),
        )
        .context(AddVolumeSnafu)?
        .service_account_name(sa_name)
        .security_context(PodSecurityContextBuilder::new().fs_group(1000).build());

    let mut pod_template = pod_builder.build_template();
    pod_template.merge_from(role.config.pod_overrides.clone());
    pod_template.merge_from(rolegroup.config.pod_overrides.clone());

    let ignore_secret_annotations = trino_authentication_config
        .hot_reloaded_secrets()
        .iter()
        .enumerate()
        .map(|(i, secret_name)| {
            (
                format!("restarter.stackable.tech/ignore-secret.{i}"),
                secret_name,
            )
        })
        .collect::<BTreeMap<_, _>>();

    let annotations =
        Annotations::try_from(ignore_secret_annotations).context(AnnotationBuildSnafu)?;

    Ok(StatefulSet {
        metadata: ObjectMetaBuilder::new()
            .name_and_namespace(trino)
            .name(resource_names.stateful_set_name().to_string())
            .ownerreference_from_resource(trino, None, Some(true))
            .context(ObjectMissingMetadataForOwnerRefSnafu)?
            .with_recommended_labels(&build_recommended_labels(
                trino,
                &resolved_product_image.app_version_label_value,
                &role_name,
                role_group_name,
            ))
            .context(MetadataBuildSnafu)?
            .with_label(RESTART_CONTROLLER_ENABLED_LABEL.to_owned())
            .with_annotations(annotations)
            .build(),
        spec: Some(StatefulSetSpec {
            pod_management_policy: Some("Parallel".to_string()),
            replicas: rolegroup.replicas.map(i32::from),
            selector: LabelSelector {
                match_labels: Some(
                    Labels::role_group_selector(trino, APP_NAME, &role_name, role_group_name)
                        .context(LabelBuildSnafu)?
                        .into(),
                ),
                ..LabelSelector::default()
            },
            service_name: Some(resource_names.headless_service_name().to_string()),
            template: pod_template,
            volume_claim_templates: Some(persistent_volume_claims),
            ..StatefulSetSpec::default()
        }),
        status: None,
    })
}

/// Give a secret name and an optional key in the secret to use.
/// The value from the key will be set into the given env var name.
/// If not secret key is given, the env var name will be used as the secret key.
fn env_var_from_secret(secret_name: &str, secret_key: Option<&str>, env_var: &str) -> EnvVar {
    EnvVar {
        name: env_var.to_string(),
        value_from: Some(EnvVarSource {
            secret_key_ref: Some(SecretKeySelector {
                optional: Some(false),
                name: secret_name.to_string(),
                key: secret_key.unwrap_or(env_var).to_string(),
            }),
            ..EnvVarSource::default()
        }),
        ..EnvVar::default()
    }
}

fn container_ports(cluster: &ValidatedCluster) -> Vec<ContainerPort> {
    let mut ports = vec![ContainerPort {
        name: Some(METRICS_PORT_NAME.to_string()),
        container_port: METRICS_PORT.into(),
        protocol: Some("TCP".to_string()),
        ..ContainerPort::default()
    }];

    if cluster.server_tls_enabled() {
        ports.push(ContainerPort {
            name: Some(HTTPS_PORT_NAME.to_string()),
            container_port: HTTPS_PORT.into(),
            protocol: Some("TCP".to_string()),
            ..ContainerPort::default()
        });
    } else {
        ports.push(ContainerPort {
            name: Some(HTTP_PORT_NAME.to_string()),
            container_port: HTTP_PORT.into(),
            protocol: Some("TCP".to_string()),
            ..ContainerPort::default()
        })
    }

    ports
}

fn startup_probe(cluster: &ValidatedCluster) -> Probe {
    Probe {
        exec: Some(finished_starting_probe(cluster)),
        period_seconds: Some(5),
        // Give the coordinator or worker 10 minutes to start up
        failure_threshold: Some(120),
        timeout_seconds: Some(3),
        ..Default::default()
    }
}

fn readiness_probe(cluster: &ValidatedCluster) -> Probe {
    Probe {
        http_get: Some(http_get_probe(cluster)),
        period_seconds: Some(5),
        failure_threshold: Some(1),
        timeout_seconds: Some(3),
        ..Probe::default()
    }
}

fn liveness_probe(cluster: &ValidatedCluster) -> Probe {
    Probe {
        http_get: Some(http_get_probe(cluster)),
        period_seconds: Some(5),
        // Coordinators are currently not highly available, so you always have a singe instance.
        // Restarting it causes all queries to fail, so let's not restart it directly after the first
        // probe failure, but wait for 3 failures
        // NOTE: This also applies to workers
        failure_threshold: Some(3),
        timeout_seconds: Some(3),
        ..Probe::default()
    }
}

/// Check that `/v1/info` returns `200`.
///
/// This is the same probe as the [upstream helm-chart](https://github.com/trinodb/charts/blob/7cd0a7bff6c52e0ee6ca6d5394cd72c150ad4379/charts/trino/templates/deployment-coordinator.yaml#L214)
/// is using.
fn http_get_probe(cluster: &ValidatedCluster) -> HTTPGetAction {
    let (schema, port_name) = if cluster.server_tls_enabled() {
        ("HTTPS", HTTPS_PORT_NAME)
    } else {
        ("HTTP", HTTP_PORT_NAME)
    };

    HTTPGetAction {
        port: IntOrString::String(port_name.to_string()),
        scheme: Some(schema.to_string()),
        path: Some("/v1/info".to_string()),
        ..Default::default()
    }
}

/// Wait until `/v1/info` returns `"starting":false`.
///
/// This probe works on coordinators and workers.
fn finished_starting_probe(cluster: &ValidatedCluster) -> ExecAction {
    let port = cluster.exposed_port();
    let schema = if cluster.server_tls_enabled() {
        "https"
    } else {
        "http"
    };

    ExecAction {
        command: Some(vec![
            "/bin/bash".to_string(),
            "-x".to_string(),
            "-euo".to_string(),
            "pipefail".to_string(),
            "-c".to_string(),
            format!(
                "curl --fail --insecure {schema}://127.0.0.1:{port}/v1/info | grep --silent '\\\"starting\\\":false'"
            ),
        ]),
    }
}

fn create_tls_volume(
    volume_name: &str,
    tls_secret_class: &str,
    requested_secret_lifetime: &Duration,
    listener_scope: Option<String>,
) -> Result<Volume> {
    let mut secret_volume_source_builder = SecretOperatorVolumeSourceBuilder::new(
        tls_secret_class,
        SecretClassVolumeProvisionParts::PublicPrivate,
    );

    secret_volume_source_builder
        .with_pod_scope()
        .with_format(SecretFormat::TlsPkcs12)
        .with_tls_pkcs12_password(STACKABLE_TLS_STORE_PASSWORD)
        .with_auto_tls_cert_lifetime(*requested_secret_lifetime);

    if let Some(listener_scope) = &listener_scope {
        secret_volume_source_builder.with_listener_volume_scope(listener_scope);
    }

    Ok(VolumeBuilder::new(volume_name)
        .ephemeral(
            secret_volume_source_builder
                .build()
                .context(TlsCertSecretClassVolumeBuildSnafu)?,
        )
        .build())
}

#[allow(clippy::too_many_arguments)]
fn tls_volume_mounts(
    trino: &v1alpha1::TrinoCluster,
    trino_role: &TrinoRole,
    pod_builder: &mut PodBuilder,
    cb_prepare: &mut ContainerBuilder,
    cb_trino: &mut ContainerBuilder,
    catalogs: &[CatalogConfig],
    requested_secret_lifetime: &Duration,
    resolved_fte_config: &Option<fault_tolerant_execution::ResolvedFaultTolerantExecutionConfig>,
    resolved_spooling_config: &Option<client_protocol::ResolvedClientProtocolConfig>,
    trino_opa_config: &Option<TrinoOpaConfig>,
) -> Result<()> {
    if let Some(server_tls) = trino.get_server_tls() {
        cb_prepare
            .add_volume_mount("server-tls-mount", STACKABLE_MOUNT_SERVER_TLS_DIR)
            .context(AddVolumeMountSnafu)?;
        cb_trino
            .add_volume_mount("server-tls-mount", STACKABLE_MOUNT_SERVER_TLS_DIR)
            .context(AddVolumeMountSnafu)?;
        pod_builder
            .add_volume(create_tls_volume(
                "server-tls-mount",
                server_tls,
                requested_secret_lifetime,
                // add listener
                secret_volume_listener_scope(trino_role),
            )?)
            .context(AddVolumeSnafu)?;
    }

    cb_prepare
        .add_volume_mount("server-tls", STACKABLE_SERVER_TLS_DIR)
        .context(AddVolumeMountSnafu)?;
    cb_trino
        .add_volume_mount("server-tls", STACKABLE_SERVER_TLS_DIR)
        .context(AddVolumeMountSnafu)?;
    pod_builder
        .add_empty_dir_volume("server-tls", None)
        .context(AddVolumeSnafu)?;

    cb_prepare
        .add_volume_mount("client-tls", STACKABLE_CLIENT_TLS_DIR)
        .context(AddVolumeMountSnafu)?;
    cb_trino
        .add_volume_mount("client-tls", STACKABLE_CLIENT_TLS_DIR)
        .context(AddVolumeMountSnafu)?;
    pod_builder
        .add_empty_dir_volume("client-tls", None)
        .context(AddVolumeSnafu)?;

    if let Some(internal_tls) = trino.get_internal_tls() {
        cb_prepare
            .add_volume_mount("internal-tls-mount", STACKABLE_MOUNT_INTERNAL_TLS_DIR)
            .context(AddVolumeMountSnafu)?;
        cb_trino
            .add_volume_mount("internal-tls-mount", STACKABLE_MOUNT_INTERNAL_TLS_DIR)
            .context(AddVolumeMountSnafu)?;
        pod_builder
            .add_volume(create_tls_volume(
                "internal-tls-mount",
                internal_tls,
                requested_secret_lifetime,
                None,
            )?)
            .context(AddVolumeSnafu)?;

        cb_prepare
            .add_volume_mount("internal-tls", STACKABLE_INTERNAL_TLS_DIR)
            .context(AddVolumeMountSnafu)?;
        cb_trino
            .add_volume_mount("internal-tls", STACKABLE_INTERNAL_TLS_DIR)
            .context(AddVolumeMountSnafu)?;
        pod_builder
            .add_empty_dir_volume("internal-tls", None)
            .context(AddVolumeSnafu)?;
    }

    // catalogs
    for catalog in catalogs {
        cb_prepare
            .add_volume_mounts(catalog.volume_mounts.clone())
            .context(AddVolumeMountSnafu)?;
        cb_trino
            .add_volume_mounts(catalog.volume_mounts.clone())
            .context(AddVolumeMountSnafu)?;
        pod_builder
            .add_volumes(catalog.volumes.clone())
            .context(AddVolumeSnafu)?;
    }

    // Add OPA TLS certs if configured
    if let Some((tls_secret_class, tls_mount_path)) =
        trino_opa_config.as_ref().and_then(|opa_config| {
            opa_config
                .tls_secret_class
                .as_ref()
                .zip(opa_config.tls_mount_path())
        })
    {
        cb_prepare
            .add_volume_mount(OPA_TLS_VOLUME_NAME, &tls_mount_path)
            .context(AddVolumeMountSnafu)?;

        let opa_tls_volume = VolumeBuilder::new(OPA_TLS_VOLUME_NAME)
            .ephemeral(
                SecretOperatorVolumeSourceBuilder::new(
                    tls_secret_class,
                    SecretClassVolumeProvisionParts::PublicPrivate,
                )
                .build()
                .context(TlsCertSecretClassVolumeBuildSnafu)?,
            )
            .build();

        pod_builder
            .add_volume(opa_tls_volume)
            .context(AddVolumeSnafu)?;
    }

    // fault tolerant execution S3 credentials and other resources
    if let Some(resolved_fte) = resolved_fte_config {
        cb_prepare
            .add_volume_mounts(resolved_fte.volume_mounts.clone())
            .context(AddVolumeMountSnafu)?;
        cb_trino
            .add_volume_mounts(resolved_fte.volume_mounts.clone())
            .context(AddVolumeMountSnafu)?;
        pod_builder
            .add_volumes(resolved_fte.volumes.clone())
            .context(AddVolumeSnafu)?;
    }

    // client spooling S3 credentials and other resources
    if let Some(resolved_spooling) = resolved_spooling_config {
        cb_prepare
            .add_volume_mounts(resolved_spooling.volume_mounts.clone())
            .context(AddVolumeMountSnafu)?;
        cb_trino
            .add_volume_mounts(resolved_spooling.volume_mounts.clone())
            .context(AddVolumeMountSnafu)?;
        pod_builder
            .add_volumes(resolved_spooling.volumes.clone())
            .context(AddVolumeSnafu)?;
    }

    Ok(())
}
