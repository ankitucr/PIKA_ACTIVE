#!/usr/bin/env bash
set -euo pipefail

: "${IMAGE_REPOSITORY:?Set IMAGE_REPOSITORY to a registry/repository, e.g. ghcr.io/owner/pika-attestor-runner}"
IMAGE_TAG="${IMAGE_TAG:-phase37-4}"
IMAGE="${IMAGE_REPOSITORY}:${IMAGE_TAG}"
DIGEST_FILE="$(mktemp)"
trap 'rm -f "$DIGEST_FILE"' EXIT

podman build --pull -f host_attestor/runner.Dockerfile -t "$IMAGE" .
podman push --digestfile "$DIGEST_FILE" "$IMAGE"
DIGEST="$(tr -d '\r\n' < "$DIGEST_FILE")"

[[ "$DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]] || {
  echo "Registry did not return a valid immutable image digest." >&2
  exit 1
}

echo
echo "PIN THIS EXACT IMAGE IN host-config.json:"
echo "${IMAGE_REPOSITORY}@${DIGEST}"
echo
echo "Do not configure a mutable tag. Pull the digest on the attestor host before enabling the service."
