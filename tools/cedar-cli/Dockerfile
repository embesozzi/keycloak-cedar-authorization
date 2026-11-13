# Official Cedar CLI (`cedar`) at the exact version the extension uses.
#
# The version must match the Cedar core inside cedar-java: cedar-java 4.10.0 is built on
# cedar-policy 4.10.0 (cedar-java/CedarJavaFFI/Cargo.toml at tag v4.10.0). The Cedar project only
# attaches pre-built CLI binaries to releases from cedar-policy-cli-v4.12.0 on, so 4.10.0 is
# compiled here from the official crate (crates.io: cedar-policy-cli 4.10.0, requires Rust 1.89).
#
# Build:  docker build -t cedar-cli:4.10.0 tools/cedar-cli
# Run:    docker run --rm -v "$PWD:/work" cedar-cli:4.10.0 --help
#
# Bump CEDAR_VERSION together with cedar-java in pom.xml.
ARG CEDAR_VERSION=4.10.0

FROM rust:1.89-slim-bookworm AS build
ARG CEDAR_VERSION
RUN cargo install --locked cedar-policy-cli --version "${CEDAR_VERSION}" --root /out

FROM debian:bookworm-slim
COPY --from=build /out/bin/cedar /usr/local/bin/cedar
WORKDIR /work
ENTRYPOINT ["cedar"]
