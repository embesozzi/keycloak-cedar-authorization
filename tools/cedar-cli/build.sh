#!/usr/bin/env bash
# Builds the official Cedar CLI image (tools/cedar-cli/Dockerfile).
set -euo pipefail
cd "$(dirname "$0")/../.."

docker build -t cedar-cli:4.10.0 tools/cedar-cli
