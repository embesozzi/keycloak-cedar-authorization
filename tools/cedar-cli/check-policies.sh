#!/usr/bin/env bash
# Checks formatting and validates the Cedar policies of every <folder>/<resource-server>/.
# Usage: tools/cedar-cli/check-policies.sh [folder]   (default: tests/policies)
# The schema is the built-in Keycloak schema plus the folder's schema, as in Keycloak.
# Run tools/cedar-cli/build.sh first.
set -euo pipefail
cd "$(dirname "$0")/../.."
mkdir -p target/cedar

POLICIES=${1:-tests/policies}
for dir in "$POLICIES"/*/; do
  name=$(basename "$dir")
  echo "== $name"
  cat src/main/resources/cedar/keycloak.cedarschema "$dir/schema.cedarschema" > "target/cedar/$name.cedarschema"
  cat "$dir"*.cedar > "target/cedar/$name.cedar"

  for policy in "$dir"*.cedar; do
    echo "format:   $policy"
    tools/cedar-cli/run.sh format --check --policies "$policy" > /dev/null
  done

  echo "validate: $dir*.cedar against keycloak.cedarschema + $dir""schema.cedarschema"
  tools/cedar-cli/run.sh validate --schema "target/cedar/$name.cedarschema" --policies "target/cedar/$name.cedar" --deny-warnings
done
