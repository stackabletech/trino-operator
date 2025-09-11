# FROM stackable/image/stackable-devel AS truststore-merger
FROM registry.access.redhat.com/ubi9/ubi-minimal@sha256:383329bf9c4f968e87e85d30ba3a5cb988a3bbde28b8e4932dcd3a025fd9c98c AS truststore-merger


RUN microdnf update -y
RUN microdnf install -y gcc findutils git
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

ENV CARGO_CYCLONEDX_CRATE_VERSION=0.5.7
ENV CARGO_AUDITABLE_CRATE_VERSION=0.6.6
RUN . "$HOME/.cargo/env" && cargo --locked --quiet install cargo-cyclonedx@"$CARGO_CYCLONEDX_CRATE_VERSION" cargo-auditable@"$CARGO_AUDITABLE_CRATE_VERSION" && rustup toolchain install

RUN microdnf install -y openssl-devel pkg-config













# TRASH ABOVE!!!

# docker build . -t oci.stackable.tech/sdp/trino:476-stackable0.0.0-dev-with-merger

RUN echo "invalidate cache 2 :)"

RUN <<EOF
git clone --depth 1 --branch "feat/truststore-merger" https://github.com/stackabletech/secret-operator
cd ./secret-operator
. "$HOME/.cargo/env"
cargo auditable --quiet build --release --package truststore-merger && cargo cyclonedx --all --spec-version 1.5 --describe binaries
EOF

FROM oci.stackable.tech/sdp/trino:476-stackable0.0.0-dev AS final

COPY --from=truststore-merger --chown=stackable:0 /secret-operator/target/release/truststore-merger /stackable/truststore-merger
