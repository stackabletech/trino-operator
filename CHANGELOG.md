# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Changed

- `operator-rs` `0.4.0` → `0.7.0` ([#81]).
- User authentication now provided via secret instead of custom resource ([#81]).
- User authentication not exposed in configmap anymore ([#81]).
- TLS certificates / keystore now retrieved via secret-operator ([#81]).
- The Trino version is now string instead of enum ([#81]).

[#81]: https://github.com/stackabletech/trino-operator/pull/81


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
