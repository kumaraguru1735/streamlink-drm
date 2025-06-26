#!/usr/bin/env bash

set -euo pipefail

ABI="${1}"
ENTRY="${2}"

# ----

log() {
  echo "[build-docker.sh]" "$@"
}

# ----

cd /app

# Set up Python environment
PYTHON="/opt/python/${ABI}/bin/python"
PIP="/opt/python/${ABI}/bin/pip"

log "Setting up Python environment"
log "Python: ${PYTHON}"
log "Pip: ${PIP}"

# Update pip
"${PIP}" install --disable-pip-version-check --no-cache-dir --upgrade pip

# Install dependencies
log "Installing dependencies"
"${PIP}" install --disable-pip-version-check --no-cache-dir -r requirements.txt

# Install the application from source
log "Installing application from source"
"${PIP}" install --disable-pip-version-check --no-cache-dir ./source.git

# Create version info
VERSION=$("${PYTHON}" -c "import ${ENTRY}; print(${ENTRY}.__version__)" 2>/dev/null || \
          "${PYTHON}" -c "from ${ENTRY} import __version__; print(__version__)" 2>/dev/null || \
          "${PYTHON}" -c "import pkg_resources; print(pkg_resources.get_distribution('streamlink').version)")
echo "${VERSION}" > version.txt
log "Version: ${VERSION}"

# Install Python into AppDir
log "Installing Python into AppDir"
mkdir -p AppDir/usr/bin AppDir/usr/lib
cp -r "/opt/python/${ABI}" "AppDir/usr/lib/"
ln -sf "../lib/${ABI}/bin/python" "AppDir/usr/bin/python"

# Install site-packages
SITE_PACKAGES="AppDir/usr/lib/${ABI}/lib/python$(echo ${ABI} | sed 's/cp\([0-9]\)\([0-9]\+\).*/\1.\2/')/site-packages"
mkdir -p "${SITE_PACKAGES}"

# Copy installed packages
"${PIP}" show streamlink | grep Location | cut -d' ' -f2 | while read location; do
  if [[ -d "${location}" ]]; then
    cp -r "${location}"/* "${SITE_PACKAGES}/"
  fi
done

# Download and set up AppImage tool
log "Setting up AppImage tool"
APPIMAGE_TOOL="https://github.com/AppImage/AppImageKit/releases/download/continuous/appimagetool-$(uname -m).AppImage"
curl -Lo appimagetool "${APPIMAGE_TOOL}"
chmod +x appimagetool

# Create AppImage
log "Creating AppImage"
./appimagetool --no-appstream AppDir out.AppImage

log "AppImage created successfully"
