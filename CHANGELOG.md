# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

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
- `operator-rs` `0.31.0` -> `0.39.0` ([#378], [#380], [#400], [#405]).
- Bumped stackable image versions to `23.4.0-rc2` ([#378], [#380]).
- Fragmented `TrinoConfig` ([#379]).
- Enabled logging and log aggregation ([#380]).

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
