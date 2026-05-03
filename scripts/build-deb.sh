#!/usr/bin/env bash
set -euo pipefail

VERSION="${VERSION:-0.1.0}"
ARCH="${ARCH:-amd64}"
DIST_DIR="${DIST_DIR:-dist}"
PACKAGE_NAME="vfw"
FULL_BUILD="${FULL_BUILD:-false}"
STAGING_DIR="${DIST_DIR}/pkgroot"
COMMIT="${COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || echo unknown)}"
LDFLAGS="-X vfw/internal/buildinfo.Version=${VERSION} -X vfw/internal/buildinfo.Commit=${COMMIT}"

DEB_SUFFIX=""
if [ "${FULL_BUILD}" = "true" ]; then
    DEB_SUFFIX="-full"
fi
OUTPUT_DEB="${DIST_DIR}/${PACKAGE_NAME}_${VERSION}_${ARCH}${DEB_SUFFIX}.deb"

mkdir -p "${DIST_DIR}"
rm -rf "${STAGING_DIR}"
mkdir -p "${STAGING_DIR}"

cp -a packaging/deb/. "${STAGING_DIR}/"
mkdir -p "${STAGING_DIR}/usr/local/bin"

GOOS=linux GOARCH="${ARCH}" CGO_ENABLED=0 go build -trimpath -ldflags "${LDFLAGS}" -o "${STAGING_DIR}/usr/local/bin/vfw" ./cmd/vfw

if [ "${FULL_BUILD}" = "true" ]; then
    echo "Building full package with bundled mmdb files..."
    GEOIP_ASN_URL="${GEOIP_ASN_URL:-https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-ASN.mmdb}"
    GEOIP_COUNTRY_URL="${GEOIP_COUNTRY_URL:-https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb}"
    GEOIP_CITY_URL="${GEOIP_CITY_URL:-https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb}"

    for url in "${GEOIP_ASN_URL}" "${GEOIP_COUNTRY_URL}" "${GEOIP_CITY_URL}"; do
        fname="$(basename "${url}")"
        echo "  downloading ${fname}..."
        curl -fsSL --retry 3 -o "${STAGING_DIR}/usr/local/bin/${fname}" "${url}"
    done

    # Enable mmdb-disabled mode in the default config for air-gapped deployments.
    sed -i 's/^# export VFW_MMDB_DISABLED=true/export VFW_MMDB_DISABLED=true/' "${STAGING_DIR}/etc/default/vfw"
fi

sed -i "s/__VERSION__/${VERSION}/g" "${STAGING_DIR}/DEBIAN/control"
sed -i "s/__ARCH__/${ARCH}/g" "${STAGING_DIR}/DEBIAN/control"

chmod 0755 "${STAGING_DIR}/DEBIAN/postinst" "${STAGING_DIR}/DEBIAN/prerm"

dpkg-deb --build --root-owner-group "${STAGING_DIR}" "${OUTPUT_DEB}"
echo "Built ${OUTPUT_DEB}"
