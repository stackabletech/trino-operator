# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

## [25.7.0] - 2025-07-23

## [25.7.0-rc1] - 2025-07-18

### Added

- Adds new telemetry CLI arguments and environment variables ([#739]).
  - Use `--file-log-max-files` (or `FILE_LOG_MAX_FILES`) to limit the number of log files kept.
  - Use `--file-log-rotation-period` (or `FILE_LOG_ROTATION_PERIOD`) to configure the frequency of rotation.
  - Use `--console-log-format` (or `CONSOLE_LOG_FORMAT`) to set the format to `plain` (default) or `json`.
- Add Listener integration for Trino ([#753]).
- Add support for Trino 476 ([#755]).
- Add internal headless service in addition to the metrics service ([#766]).
- Add RBAC rule to helm template for automatic cluster domain detection ([#771]).

### Changed

- BREAKING: Replace stackable-operator `initialize_logging` with stackable-telemetry `Tracing` ([#728], [#735], [#739]).
  - The console log level was set by `TRINO_OPERATOR_LOG`, and is now set by `CONSOLE_LOG_LEVEL`.
  - The file log level was set by `TRINO_OPERATOR_LOG`, and is now set by `FILE_LOG_LEVEL`.
  - The file log directory was set by `TRINO_OPERATOR_LOG_DIRECTORY`, and is now set
    by `FILE_LOG_DIRECTORY` (or via `--file-log-directory <DIRECTORY>`).
  - Replace stackable-operator `print_startup_string` with `tracing::info!` with fields.
- BREAKING: Inject the vector aggregator address into the vector config using the env var `VECTOR_AGGREGATOR_ADDRESS` instead
    of having the operator write it to the vector config ([#734]).
- test: Bump HDFS to `3.4.1` ([#741]).
- test: Bump to Vector `0.46.1` ([#743]).
- test: Bump OPA `1.4.2` ([#745]).
- Use versioned common structs ([#748]).
- BREAKING: Previously this operator would hardcode the UID and GID of the Pods being created to 1000/0, this has changed now ([#752])
  - The `runAsUser` and `runAsGroup` fields will not be set anymore by the operator
  - The defaults from the docker images itself will now apply, which will be different from 1000/0 going forward
  - This is marked as breaking because tools and policies might exist, which require these fields to be set
- Deprecate Trino 470 ([#755]).
- test: support custom versions ([#760]).
- BREAKING: Bump stackable-operator to 0.94.0 and update other dependencies ([#771]).
  - The default Kubernetes cluster domain name is now fetched from the kubelet API unless explicitly configured.
  - This requires operators to have the RBAC permission to get nodes/proxy in the apiGroup "". The helm-chart takes care of this.
  - The CLI argument `--kubernetes-node-name` or env variable `KUBERNETES_NODE_NAME` needs to be set. The helm-chart takes care of this.
- The operator helm-chart now grants RBAC `patch` permissions on `events.k8s.io/events`,
  so events can be aggregated (e.g. "error happened 10 times over the last 5 minutes") ([#774]).

### Fixed

- Use `json` file extension for log files ([#733]).
- Fix a bug where changes to ConfigMaps that are referenced in the TrinoCluster spec didn't trigger a reconciliation ([#734]).
- BREAKING: The PersistentVolumeClaims for coordinator and workers have been removed ([#769])
  - They caused problems, as Trino kept it's process ID in `/stackable/data/var/run/launcher.pid`.
    A forceful stop (e.g. OOMKilled) could result in a leftover PID in this file.
    In this case Trino would refuse startup with `trino ERROR: already running as 21`.
    As the PersistentVolumeClaims didn't store any actual data, they have been removed.
  - Upgrading will result in the error message `Failed to reconcile object [...]: Forbidden: updates to   statefulset spec for fields other than [...] are forbidden`
    as Kubernetes currently does not allow changing the `volumeClaimTemplates` field. Simply delete the mentioned StatefulSet, the operator will re-create it.
  - You might want to clean up now useless PVCs.
    Tip: You can list all Trino-related PVCs using `kubectl get pvc -l app.kubernetes.io/name=trino`.
  - The `.spec.(coordinators|workers).config.resources.storage.data` field has been removed, as it's not needed anymore.
- Allow uppercase characters in domain names ([#771]).

### Removed

- Remove support for Trino 455 ([#755]).
- Remove the `lastUpdateTime` field from the stacklet status ([#771]).
- Remove role binding to legacy service accounts ([#771]).

[#728]: https://github.com/stackabletech/trino-operator/pull/728
[#734]: https://github.com/stackabletech/trino-operator/pull/734
[#733]: https://github.com/stackabletech/trino-operator/pull/733
[#735]: https://github.com/stackabletech/trino-operator/pull/735
[#739]: https://github.com/stackabletech/trino-operator/pull/739
[#741]: https://github.com/stackabletech/trino-operator/pull/741
[#743]: https://github.com/stackabletech/trino-operator/pull/743
[#745]: https://github.com/stackabletech/trino-operator/pull/745
[#748]: https://github.com/stackabletech/trino-operator/pull/748
[#752]: https://github.com/stackabletech/trino-operator/pull/752
[#753]: https://github.com/stackabletech/trino-operator/pull/753
[#755]: https://github.com/stackabletech/trino-operator/pull/755
[#760]: https://github.com/stackabletech/trino-operator/pull/760
[#766]: https://github.com/stackabletech/trino-operator/pull/766
[#769]: https://github.com/stackabletech/trino-operator/pull/769
[#771]: https://github.com/stackabletech/trino-operator/pull/771
[#774]: https://github.com/stackabletech/trino-operator/pull/774

## [25.3.0] - 2025-03-21

### Added

- The lifetime of auto generated TLS certificates is now configurable with the role and roleGroup
  config property `requestedSecretLifetime`. This helps reduce frequent Pod restarts ([#676]).
- Run a `containerdebug` process in the background of each Trino container to collect debugging information ([#687]).
- Support configuring JVM arguments ([#677]).
- Aggregate emitted Kubernetes events on the CustomResources ([#677]).
- Support for Trino 470 ([#705]).
- Support removing properties from catalogs.
  This is helpful, because Trino fails to start in case you have any unused config properties ([#713]).
- Support `access-control.properties` in configOverrides ([#721]).

### Changed

- Increased the default temporary secret lifetime for coordinators from 1 day to 15 days.
  This is because Trino currently does not offer a HA setup for them, a restart kills all running queries ([#694]).
- Default to OCI for image metadata and product image selection ([#695]).
- Explicitly set `fs.native-s3.enabled=true` and `fs.hadoop.enabled=true` in applicable catalog config properties ([#705]).
  - Trino 470 requires the native S3 implementation to be used.
- BREAKING: Always set the S3 region ([#705]).
  - Previously Trino used the hadoop s3 implementation which auto-detected the region from the
    endpoint if it was not provided, falling back to `us-east-2`.
  - The default is now `us-east-1`. Please set the region explicitly if you are using a different
    one.
- Bump `stackable-versioned` to 0.6.0 ([#722]).

### Fixed

- Add a startupProbe, which checks via `/v1/info` that the coordinator/worker have finished starting.
  Also migrate the other probes from `tcpSocket` to `httpGet` on `/v1/info` ([#715], [#717]).

[#676]: https://github.com/stackabletech/trino-operator/pull/676
[#677]: https://github.com/stackabletech/trino-operator/pull/677
[#687]: https://github.com/stackabletech/trino-operator/pull/687
[#694]: https://github.com/stackabletech/trino-operator/pull/694
[#695]: https://github.com/stackabletech/trino-operator/pull/695
[#705]: https://github.com/stackabletech/trino-operator/pull/705
[#713]: https://github.com/stackabletech/trino-operator/pull/713
[#715]: https://github.com/stackabletech/trino-operator/pull/715
[#717]: https://github.com/stackabletech/trino-operator/pull/717
[#721]: https://github.com/stackabletech/trino-operator/pull/721
[#722]: https://github.com/stackabletech/trino-operator/pull/722

## [24.11.1] - 2025-01-10

### Fixed

- Fix OIDC endpoint construction in case the `rootPath` does have a trailing slash ([#673]).
- BREAKING: Use distinct ServiceAccounts for the Stacklets, so that multiple Stacklets can be
  deployed in one namespace. Existing Stacklets will use the newly created ServiceAccounts after
  restart ([#672]).

[#672]: https://github.com/stackabletech/trino-operator/pull/672
[#673]: https://github.com/stackabletech/trino-operator/pull/673

## [24.11.0] - 2024-11-18

### Added

- Added support for Trino 455 ([#638]).
- The operator can now run on Kubernetes clusters using a non-default cluster domain.
  Use the env var `KUBERNETES_CLUSTER_DOMAIN` or the operator Helm chart property `kubernetesClusterDomain` to set a non-default cluster domain ([#655]).

### Changed

- Reduce CRD size from `984KB` to `131KB` by accepting arbitrary YAML input instead of the underlying schema for the following fields ([#631]):
  - `podOverrides`
  - `affinity`

### Fixed

- BREAKING: The fields `connection` and `host` on `S3Connection` as well as `bucketName` on `S3Bucket`are now mandatory ([#646]).
- Don't ignore envOverrides ([#633]).
- Don't print credentials to STDOUT during startup. Ideally, we should use [config-utils](https://github.com/stackabletech/config-utils), but that's not easy (see [our experimental branch](https://github.com/stackabletech/trino-operator/tree/fix/secret-printing)) ([#634]).
- Invalid `TrinoCluster`, `TrinoCatalog` or `AuthenticationClass` objects don't stop the operator from reconciliation ([#657])

### Removed

- Removed support for Trino 414 and 442 ([#638]).

[#631]: https://github.com/stackabletech/trino-operator/pull/631
[#633]: https://github.com/stackabletech/trino-operator/pull/633
[#634]: https://github.com/stackabletech/trino-operator/pull/634
[#638]: https://github.com/stackabletech/trino-operator/pull/638
[#646]: https://github.com/stackabletech/trino-operator/pull/646
[#655]: https://github.com/stackabletech/trino-operator/pull/655
[#657]: https://github.com/stackabletech/trino-operator/pull/657

## [24.7.0] - 2024-07-24

### Added

- Support row filters and column masks in Rego rules ([#559]).
- Support for version `451` ([#609]).

### Changed

- BREAKING: Change the username which triggers graceful shutdown from `admin` to `graceful-shutdown-user` for more expressiveness (e.g. in the Trino policies).
  This is a breaking change because users need to ensure that the user `graceful-shutdown-user` has the required permissions to initiate a graceful shutdown ([#573]).
- Bump `stackable-operator` to 0.70.0, `product-config` to 0.7.0, and other dependencies ([#611]).

### Fixed

- Processing of corrupted log events fixed; If errors occur, the error
  messages are added to the log event ([#598]).

### Removed

- Support for version `428` ([#609]).

[#559]: https://github.com/stackabletech/trino-operator/pull/559
[#573]: https://github.com/stackabletech/trino-operator/pull/573
[#598]: https://github.com/stackabletech/trino-operator/pull/598
[#609]: https://github.com/stackabletech/trino-operator/pull/609
[#611]: https://github.com/stackabletech/trino-operator/pull/611

## [24.3.0] - 2024-03-20

### Added

- Various documentation of the CRD ([#510]).
- Helm: support labels in values.yaml ([#528]).
- Delta Lake connector ([#531]).
- Support for version `442` ([#557]).
- Add support for OpenID Connect ([#501]).

### Fixed

- Add `core-site.xml` when configuring HDFS connection ([#526]).

[#510]: https://github.com/stackabletech/trino-operator/pull/510
[#526]: https://github.com/stackabletech/trino-operator/pull/526
[#528]: https://github.com/stackabletech/trino-operator/pull/528
[#501]: https://github.com/stackabletech/trino-operator/pull/501
[#531]: https://github.com/stackabletech/trino-operator/pull/531
[#557]: https://github.com/stackabletech/trino-operator/pull/557

## [23.11.0] - 2023-11-24

### Added

- Use [graceful shutdown](https://trino.io/docs/current/admin/graceful-shutdown.html) for workers ([#461], [#463], [#466], [#474]).
- Default stackableVersion to operator version ([#441]).
- Configuration overrides for the JVM security properties, such as DNS caching ([#460]).
- Support PodDisruptionBudgets ([#481]).
- Added support for version 428 with new opa authorizer ([#491]).

### Fixed

- Let controller watch `AuthenticationClasses` ([#449]).

### Changed

- `operator-rs` `0.44.0` -> `0.55.0` ([#441], [#453], [#470], [#481], [#491]).
- `vector` `0.26.0` -> `0.33.0` ([#453], [#491]).
- Let secret-operator handle certificate conversion ([#470]).
- [BREAKING]: Version 428 uses the new OPA authorizer from <https://github.com/bloomberg/trino/tree/add-open-policy-agent> which requires existing rego rules to be changed ([#491]).

### Removed

- Removed support for versions 377, 387, 395, 396, 403 ([#491]).

[#441]: https://github.com/stackabletech/trino-operator/pull/441
[#449]: https://github.com/stackabletech/trino-operator/pull/449
[#453]: https://github.com/stackabletech/trino-operator/pull/453
[#460]: https://github.com/stackabletech/trino-operator/pull/460
[#461]: https://github.com/stackabletech/trino-operator/pull/461
[#463]: https://github.com/stackabletech/trino-operator/pull/463
[#466]: https://github.com/stackabletech/trino-operator/pull/466
[#470]: https://github.com/stackabletech/trino-operator/pull/470
[#474]: https://github.com/stackabletech/trino-operator/pull/474
[#481]: https://github.com/stackabletech/trino-operator/pull/481
[#491]: https://github.com/stackabletech/trino-operator/pull/491

## [23.7.0] - 2023-07-14

### Added

- Support for Trino v414 ([#423]).
- Generate OLM bundle for Release 23.4.0 ([#424]).
- Set explicit resources on all containers ([#434]).
- Support arbitrary connectors using the `generic` connector. This allows you to e.g. access your PostgreSQL ([#436]).
- Support `podOverride` ([#440]).

### Fixed

- Missing CRD defaults for `status.conditions` field ([#425]).
- Fixed always adding `query.max-memory-per-node` with a fixed value of 1GB (which also didn't work with the new resource defaults). Instead let Trino do it's `(JVM max memory * 0.3)` thing ([#434]).
- Increase the size limit of the log volume ([#445]).

### Changed

- `operator-rs` `0.40.2` -> `0.44.0` ([#419], [#445]).
- Use 0.0.0-dev product images for testing ([#421]).
- Use testing-tools 0.2.0 (with new trino client version) ([#421]).
- Added kuttl test suites ([#437]).
- [BREAKING]: Reworked authentication mechanism: The`clusterConfig.authentication` now requires a list of `AuthenticationClass` references instead of the `MultiUser` and `LDAP` separation ([#434]).

[#419]: https://github.com/stackabletech/trino-operator/pull/419
[#421]: https://github.com/stackabletech/trino-operator/pull/421
[#423]: https://github.com/stackabletech/trino-operator/pull/423
[#424]: https://github.com/stackabletech/trino-operator/pull/424
[#425]: https://github.com/stackabletech/trino-operator/pull/425
[#434]: https://github.com/stackabletech/trino-operator/pull/434
[#436]: https://github.com/stackabletech/trino-operator/pull/436
[#437]: https://github.com/stackabletech/trino-operator/pull/437
[#440]: https://github.com/stackabletech/trino-operator/pull/440
[#445]: https://github.com/stackabletech/trino-operator/pull/445

## [23.4.0] - 2023-04-17

### Added

- Deploy default and support custom affinities ([#391]).
- Cluster status conditions ([#403])
- Openshift compatibility ([#404]).
- Extend cluster resources for status and cluster operation (paused, stopped) ([#405])

### Changed

- [BREAKING]: Moved top level config options (TLS, Authentication, Authorization etc.) to new top level field `clusterConfig` ([#400]).
- [BREAKING]: Support specifying Service type by moving `serviceType` (which was an experimental feature) to `clusterConfig.listenerClass`.
  This enables us to later switch non-breaking to using `ListenerClasses` for the exposure of Services.
  This change is breaking, because - for security reasons - we default to the `cluster-internal` `ListenerClass`.
  If you need your cluster to be accessible from outside of Kubernetes you need to set `clusterConfig.listenerClass`
  to `external-unstable` or `external-stable` ([#406]).
- `operator-rs` `0.31.0` -> `0.40.2` ([#378], [#380], [#400], [#404], [#405]).
- Bumped stackable image versions to `23.4.0-rc2` ([#378], [#380]).
- Fragmented `TrinoConfig` ([#379]).
- Enabled logging and log aggregation ([#380]).
- Use operator-rs `build_rbac_resources` method ([#404]).

### Removed

- [BREAKING]: Removed `log_level` from `TrinoConfig` which is now set via the logging framework struct ([#380]).

[#378]: https://github.com/stackabletech/trino-operator/pull/378
[#379]: https://github.com/stackabletech/trino-operator/pull/379
[#380]: https://github.com/stackabletech/trino-operator/pull/380
[#391]: https://github.com/stackabletech/trino-operator/pull/391
[#400]: https://github.com/stackabletech/trino-operator/pull/400
[#403]: https://github.com/stackabletech/trino-operator/pull/403
[#404]: https://github.com/stackabletech/trino-operator/pull/404
[#405]: https://github.com/stackabletech/trino-operator/pull/405
[#406]: https://github.com/stackabletech/trino-operator/pull/406

## [23.1.0] - 2023-01-23

### Added

- Add support for [Google Sheets connector](https://trino.io/docs/current/connector/googlesheets.html) ([#337]).
- Add support for [Black Hole connector](https://trino.io/docs/current/connector/blackhole.html) ([#347]).
- Add support for Trino `403-stackable0.1.0` ([#358]).

### Changed

- Updated stackable image versions ([#340]).
- `operator-rs` `0.25.0` -> `0.30.2` ([#344], [#360], [#364]).
- LDAP integration tests create all resources in their namespace and not some in the default namespace ([#344]).
- Don't run init container as root and avoid chmod and chowning ([#353]).
- [BREAKING]: Use Product image selection instead of version. `spec.version` has been replaced by `spec.image` ([#356]).
- [BREAKING]: Removed tools image for init container and replaced with Trino product image. This means the latest stackable version has to be used in the product image selection ([#357])
- [BREAKING]: Use `user` and `password` Secret keys for LDAP bind credentials Secrets, instead of env var names ([#362])
- Adapted examples and tests to Hive CRD changes ([#364]).

### Fixed

- Hive catalog now properly handles hive clusters with replicas > 1 ([#348]).
- Role group selectors are now applied to the generated StatefulSets ([#360]).
- LDAP bind credentials resolution from SecretClasses now works correctly ([#367]).

[#337]: https://github.com/stackabletech/trino-operator/pull/337
[#340]: https://github.com/stackabletech/trino-operator/pull/340
[#344]: https://github.com/stackabletech/trino-operator/pull/344
[#347]: https://github.com/stackabletech/trino-operator/pull/347
[#348]: https://github.com/stackabletech/trino-operator/pull/348
[#353]: https://github.com/stackabletech/trino-operator/pull/353
[#356]: https://github.com/stackabletech/trino-operator/pull/356
[#357]: https://github.com/stackabletech/trino-operator/pull/357
[#358]: https://github.com/stackabletech/trino-operator/pull/358
[#360]: https://github.com/stackabletech/trino-operator/pull/360
[#362]: https://github.com/stackabletech/trino-operator/pull/362
[#364]: https://github.com/stackabletech/trino-operator/pull/364
[#367]: https://github.com/stackabletech/trino-operator/pull/367

## [0.8.0] - 2022-11-07

### Added

- Added support for LDAP authentication ([#306]).
- Orphaned resources are deleted ([#310]).

### Changed

- `operator-rs` `0.22.0` -> `0.25.0` ([#306]).

### Fixed

- Port 8080 missing from Coordinator service if client TLS is disabled ([#311]).

[#306]: https://github.com/stackabletech/trino-operator/pull/306
[#310]: https://github.com/stackabletech/trino-operator/pull/310
[#311]: https://github.com/stackabletech/trino-operator/pull/311

## [0.7.0] - 2022-09-22

### Added

- Add support for Trino `395-stackable0.1.0` and `396-stackable0.1.0` ([#292]).
- Add support for [Iceberg connector](https://trino.io/docs/current/connector/iceberg.html) ([#286]).
- Add support for [TPCH connector](https://trino.io/docs/current/connector/tpch.html) and [TPCDS connector](https://trino.io/docs/current/connector/tpcds.html) ([#293]).

### Fixed

- Fix not adding `configOverwrites` specified in a `TrinoCatalog` to the catalog ([#289]).

[#286]: https://github.com/stackabletech/trino-operator/pull/286
[#289]: https://github.com/stackabletech/trino-operator/pull/289
[#292]: https://github.com/stackabletech/trino-operator/pull/292
[#293]: https://github.com/stackabletech/trino-operator/pull/293

## [0.6.0] - 2022-09-08

### Changed

- BREAKING: TrinoClusters must specify a `catalogLabelSelector`. Previously all TrinoCatalogs within the same namespace where used when `catalogLabelSelector` was not specified, which is unwanted behavior ([#277]).

[#277]: https://github.com/stackabletech/trino-operator/pull/277

## [0.5.0] - 2022-09-07

### Added

- Add support for connecting to HDFS ([#263]).
- Add support for Hive 3.1.3 ([#243]).
- PVCs for data storage, cpu and memory limits are now configurable ([#270]).
- Add temporary attribute to support using ClusterIP instead of NodePort service type ([#272]).

### Changed

- BREAKING: TrinoCatalogs now have their own CRD object and get referenced by the TrinoCluster according to [ADR19](https://docs.stackable.tech/home/contributor/adr/ADR019-trino_catalog_definitions.html) and [ADR20](https://docs.stackable.tech/home/contributor/adr/ADR020-trino_catalog_usage.html) ([#263]).
- Include chart name when installing with a custom release name ([#233], [#234]).
- `operator-rs` `0.21.1` -> `0.22.0` ([#235]).
- Internal and client TLS now configurable instead of defaulting to "tls" secret class ([#244]).
- S3 TLS properly supported ([#244]).
- Introduced global `config` for `TLS` settings ([#244]).

### Fixed

- Add missing role to read S3Connection objects ([#263]).
- Disable Hive connector setting that disallow dropping tables. This check is now done by normal Trino authorization (e.g. OPA) ([#263]).

[#233]: https://github.com/stackabletech/trino-operator/pull/233
[#234]: https://github.com/stackabletech/trino-operator/pull/234
[#235]: https://github.com/stackabletech/trino-operator/pull/235
[#243]: https://github.com/stackabletech/trino-operator/pull/243
[#244]: https://github.com/stackabletech/trino-operator/pull/244
[#263]: https://github.com/stackabletech/trino-operator/pull/263
[#270]: https://github.com/stackabletech/trino-operator/pull/270
[#272]: https://github.com/stackabletech/trino-operator/pull/272

## [0.4.0] - 2022-06-30

### Added

- Reconciliation errors are now reported as Kubernetes events ([#149]).
- Use cli argument `watch-namespace` / env var `WATCH_NAMESPACE` to specify
  a single namespace to watch ([#157]).
- Moved tests from integration tests repo to operator repo ([#211]).
- Added `internal-communication.shared-secret` property which is read from (operator created secret). Must be set from Trino version 378 ([#224]).

### Changed

- `operator-rs` `0.10.0` -> `0.21.1` ([#149], [#157], [#183], [#193], [#206]).
- BREAKING: The operator now writes a `ConfigMap` for Rego rules instead of
  the custom resource for the obsolete regorule-operator. This means that
  the rego rule operator is not required anymore for authorization and
  opa-operator tag >= `0.9.0` ([#157]).
- BREAKING: `OpaConfigMapName` in CRD to `opa` using the `OpaConfig` from operator-rs ([#186]).
- Trino version to 377 ([#193]).
- Opa rego example adapted to the new `trino-opa-authorizer` ([#193]).
- BREAKING: Configuration of S3 adapted to ADR016 ([#200]).
- BREAKING: Specifying the product version has been changed to adhere to [ADR018](https://docs.stackable.tech/home/contributor/adr/ADR018-product_image_versioning.html) instead of just specifying the product version you will now have to add the Stackable image version as well, so version: 3.1.0 becomes (for example) version: 3.1.0-stackable0 ([#211])

### Removed

- `stackable-regorule-crd` dependency ([#157]).
- BREAKING: `nodeEnvironment` from CRD. Will default to the `metadata.name` field (can be overriden) ([#183]).
- BREAKING: Removed `authorization` module from CRD and code and provided the opa bundle via `ConfigMap` directly instead of generating it ([#186]).
- Possibly BREAKING: Removed `query.max-total-memory-per-node` config parameter ([#193]).

[#149]: https://github.com/stackabletech/trino-operator/pull/149
[#157]: https://github.com/stackabletech/trino-operator/pull/157
[#183]: https://github.com/stackabletech/trino-operator/pull/183
[#186]: https://github.com/stackabletech/trino-operator/pull/186
[#193]: https://github.com/stackabletech/trino-operator/pull/193
[#200]: https://github.com/stackabletech/trino-operator/pull/200
[#206]: https://github.com/stackabletech/trino-operator/pull/206
[#211]: https://github.com/stackabletech/trino-operator/pull/211
[#224]: https://github.com/stackabletech/trino-operator/pull/224

## [0.3.1] - 2022-02-17

### Changed

- Fixed `stackable/data` write permission failure in managed cloud ([#142]).
- Replaced hardcoded references in init container command to
  `stackable/keystore` ([#142]).

[#142]: https://github.com/stackabletech/trino-operator/pull/142

## [0.3.0] - 2022-02-14

### Added

- Monitoring scraping label `prometheus.io/scrape: true` ([#118]).

### Changed

- BREAKING: CRD changes. The `spec.opa` and `spec.hive` renamed to
`spec.opaConfigMapName` and `spec.hiveConfigMapName`
which only accept a String ([#131]).
- BREAKING: In case the namespace is omitted, the operator defaults to the `TrinoCluster` namespace instead of `default` ([#95]).
- User authentication now provided via secret instead of custom resource ([#81]).
- User authentication not exposed in configmap anymore ([#81]).
- TLS certificates / keystore now retrieved via secret-operator ([#81]).
- The Trino version is now a string instead of enum ([#81]).
- `operator-rs` `0.4.0` → `0.10.0` ([#81], [#95], [#118]).
- `stackable-regorule-crd` `0.2.0` → `0.6.0` ([#81], [#118]).
- Improvements to setting up (easy) insecure clusters ([#131])

[#81]: https://github.com/stackabletech/trino-operator/pull/81
[#95]: https://github.com/stackabletech/trino-operator/pull/95
[#118]: https://github.com/stackabletech/trino-operator/pull/118
[#131]: https://github.com/stackabletech/trino-operator/pull/131

## [0.2.0] - 2021-12-06

### Changed

- `operator-rs` `0.3.0` → `0.4.0` ([#32]).
- `stackable-hive-crd` `0.1.0` → `0.2.0` ([#32]).
- `stackable-regorule-crd` `0.1.0` → `0.2.0` ([#32]).
- `stackable-opa-crd` `0.4.1` → `0.5.0` ([#32]).
- Adapted pod image and container command to docker image ([#32]).
- Adapted documentation to represent new workflow with docker images ([#32]).

[#32]: https://github.com/stackabletech/trino-operator/pull/32

## [0.1.0] - 2021-10-28

### Changed

- Switched to operator-rs tag 0.3.0 ([#21])

[#21]: https://github.com/stackabletech/hdfs-operator/pull/21
