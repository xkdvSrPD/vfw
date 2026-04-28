#!/usr/bin/env bash
set -euo pipefail

VERSION="${VERSION:-0.1.0}"
ARCH="${ARCH:-amd64}"
DIST_DIR="${DIST_DIR:-dist}"
PACKAGE_NAME="vfw"
STAGING_DIR="${DIST_DIR}/pkgroot"
OUTPUT_DEB="${DIST_DIR}/${PACKAGE_NAME}_${VERSION}_${ARCH}.deb"
COMMIT="${COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || echo unknown)}"
LDFLAGS="-X vfw/internal/buildinfo.Version=${VERSION} -X vfw/internal/buildinfo.Commit=${COMMIT}"

mkdir -p "${DIST_DIR}"
rm -rf "${STAGING_DIR}"
mkdir -p "${STAGING_DIR}"

cp -a packaging/deb/. "${STAGING_DIR}/"
mkdir -p "${STAGING_DIR}/usr/local/bin"

GOOS=linux GOARCH="${ARCH}" CGO_ENABLED=0 go build -trimpath -ldflags "${LDFLAGS}" -o "${STAGING_DIR}/usr/local/bin/vfw" ./cmd/vfw

sed -i "s/__VERSION__/${VERSION}/g" "${STAGING_DIR}/DEBIAN/control"
sed -i "s/__ARCH__/${ARCH}/g" "${STAGING_DIR}/DEBIAN/control"

chmod 0755 "${STAGING_DIR}/DEBIAN/postinst" "${STAGING_DIR}/DEBIAN/prerm"

dpkg-deb --build --root-owner-group "${STAGING_DIR}" "${OUTPUT_DEB}"
echo "Built ${OUTPUT_DEB}"
