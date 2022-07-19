# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Changed

- Include chart name when installing with a custom release name ([#233], [#234]).
- `operator-rs` `0.21.1` -> `0.22.0` ([#235]).
- Add support for Hive 3.1.3 ([#243])

[#233]: https://github.com/stackabletech/trino-operator/pull/233
[#234]: https://github.com/stackabletech/trino-operator/pull/234
[#235]: https://github.com/stackabletech/trino-operator/pull/235
[#243]: https://github.com/stackabletech/trino-operator/pull/243

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
