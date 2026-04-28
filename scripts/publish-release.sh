#!/usr/bin/env bash
set -euo pipefail

: "${GITEA_API_URL:?GITEA_API_URL is required}"
: "${GITEA_REPOSITORY:?GITEA_REPOSITORY is required}"
: "${GITEA_TOKEN:?GITEA_TOKEN is required}"
: "${TAG_NAME:?TAG_NAME is required}"
: "${ARTIFACT_PATH:?ARTIFACT_PATH is required}"

OWNER="${GITEA_REPOSITORY%%/*}"
REPO="${GITEA_REPOSITORY##*/}"
RELEASE_NAME="${RELEASE_NAME:-${TAG_NAME}}"
RELEASE_BODY="${RELEASE_BODY:-Automated release for ${TAG_NAME}}"
TARGET_COMMITISH="${TARGET_COMMITISH:-${TAG_NAME}}"

if [ ! -f "${ARTIFACT_PATH}" ]; then
    echo "artifact not found: ${ARTIFACT_PATH}" >&2
    exit 1
fi

api_request() {
    local method="$1"
    local url="$2"
    shift 2
    curl --silent --show-error --fail \
        -X "${method}" \
        -H "Authorization: token ${GITEA_TOKEN}" \
        "$@" \
        "${url}"
}

release_url="${GITEA_API_URL}/repos/${OWNER}/${REPO}/releases/tags/${TAG_NAME}"
tmp_json="$(mktemp)"
status_code="$(
    curl --silent --show-error \
        -o "${tmp_json}" \
        -w "%{http_code}" \
        -H "Authorization: token ${GITEA_TOKEN}" \
        "${release_url}"
)"

if [ "${status_code}" = "200" ]; then
    release_id="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["id"])' "${tmp_json}")"
else
    create_payload="$(python3 - "${TAG_NAME}" "${TARGET_COMMITISH}" "${RELEASE_NAME}" "${RELEASE_BODY}" <<'PY'
import json
import sys
payload = {
    "tag_name": sys.argv[1],
    "target_commitish": sys.argv[2],
    "name": sys.argv[3],
    "body": sys.argv[4],
    "draft": False,
    "prerelease": False,
}
print(json.dumps(payload))
PY
)"
    api_request POST "${GITEA_API_URL}/repos/${OWNER}/${REPO}/releases" \
        -H "Content-Type: application/json" \
        -d "${create_payload}" > "${tmp_json}"
    release_id="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["id"])' "${tmp_json}")"
fi

asset_name="$(basename "${ARTIFACT_PATH}")"
asset_id="$(python3 - "${tmp_json}" "${asset_name}" <<'PY'
import json
import sys
path, target_name = sys.argv[1], sys.argv[2]
data = json.load(open(path))
for asset in data.get("assets", []):
    if asset.get("name") == target_name:
        print(asset["id"])
        break
PY
)"
if [ -n "${asset_id}" ]; then
    api_request DELETE "${GITEA_API_URL}/repos/${OWNER}/${REPO}/releases/${release_id}/assets/${asset_id}" >/dev/null
fi

api_request POST "${GITEA_API_URL}/repos/${OWNER}/${REPO}/releases/${release_id}/assets?name=${asset_name}" \
    -F "attachment=@${ARTIFACT_PATH}" >/dev/null

echo "Published ${asset_name} to release ${TAG_NAME}"
