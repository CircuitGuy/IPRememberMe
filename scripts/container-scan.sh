#!/usr/bin/env bash
# Runs container security linting (hadolint, trivy, dockle) against the built image.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

IMAGE_TAG="${IPREMEMBER_IMAGE:-ipremember:dev}"
TRIVY_VERSION="${TRIVY_VERSION:-0.51.1}"
DOCKLE_VERSION="${DOCKLE_VERSION:-0.4.14}"
HADOLINT_VERSION="${HADOLINT_VERSION:-2.12.0}"
# Hadolint args: see DEVELOPERS.md for the HADOLINT_ARGS and discussions of ignores. TODO: Remove this if going to Docker hardened.
HADOLINT_ARGS=${HADOLINT_ARGS:---ignore DL3007}
TRIVY_CACHE_DIR="${TRIVY_CACHE_DIR:-$ROOT/.cache/trivy}"
TRIVY_SEVERITY="${TRIVY_SEVERITY:-CRITICAL}"
TRIVY_IGNORE_UNFIXED="${TRIVY_IGNORE_UNFIXED:-true}"
DOCKLE_EXIT_LEVEL="${DOCKLE_EXIT_LEVEL:-WARN}"
DOCKLE_IMAGE_TAG="$DOCKLE_VERSION"
TRIVY_ARGS=()

if [[ "$DOCKLE_IMAGE_TAG" != v* ]]; then
  DOCKLE_IMAGE_TAG="v${DOCKLE_IMAGE_TAG}"
fi

if [ "${TRIVY_IGNORE_UNFIXED}" != "false" ]; then
  TRIVY_ARGS+=("--ignore-unfixed")
fi

mkdir -p "$TRIVY_CACHE_DIR"

echo "Building image for scans: ${IMAGE_TAG}"
docker build -t "$IMAGE_TAG" "$ROOT"

echo "Running hadolint on Dockerfile..."
docker run --rm -v "$ROOT":/workspace -w /workspace "hadolint/hadolint:${HADOLINT_VERSION}" hadolint $HADOLINT_ARGS Dockerfile

echo "Running trivy (${TRIVY_SEVERITY}) against ${IMAGE_TAG}..."
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$TRIVY_CACHE_DIR":/root/.cache/ \
  "aquasec/trivy:${TRIVY_VERSION}" \
  image --severity "${TRIVY_SEVERITY}" --exit-code 1 "${TRIVY_ARGS[@]}" "$IMAGE_TAG"

echo "Running dockle against ${IMAGE_TAG}..."
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  "goodwithtech/dockle:${DOCKLE_IMAGE_TAG}" \
  --exit-code 1 --exit-level "${DOCKLE_EXIT_LEVEL}" "$IMAGE_TAG"

echo "Container security checks passed."
