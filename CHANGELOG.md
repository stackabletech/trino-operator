# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added

- Reconciliation errors are now reported as Kubernetes events ([#149]).
- Use cli argument `watch-namespace` / env var `WATCH_NAMESPACE` to specify
  a single namespace to watch ([#157]).

### Changed

- `operator-rs` `0.10.0` -> `0.13.0` ([#149],[#157]).
- BREAKING: The operator now writes a `ConfigMap` for Rego rules instead of
  the custom resource for the obsolete regorule-operator. This means that 
  the rego rule operator is not required anymore for authorization and 
  opa-operator tag >= `0.9.0` ([#157]).

### Removed

- `stackable-regorule-crd` dependency ([#157]).

[#149]: https://github.com/stackabletech/trino-operator/pull/149
[#157]: https://github.com/stackabletech/trino-operator/pull/157

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
