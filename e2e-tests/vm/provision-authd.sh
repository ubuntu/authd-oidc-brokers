#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
LIB_DIR="${SCRIPT_DIR}/lib"
SSH="${SCRIPT_DIR}/ssh.sh"
CONFIG_FILE="${SCRIPT_DIR}/config.sh"

usage(){
    cat << EOF
Usage: $0 [--config-file <file>]

Options:
   --config-file <file>  Path to the configuration file (default: config.sh)
  -h, --help             Show this help message and exit

Provisions authd in the VM for end-to-end tests
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --config-file)
            CONFIG_FILE="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        -*)
            echo >&2 "Unknown option: $1"
            exit 1
            ;;
        *)
            echo >&2 "Unexpected positional argument: $1"
            exit 1
    esac
done

if [ ! -f "${CONFIG_FILE}" ]; then
    echo "Configuration file '${CONFIG_FILE}' not found." >&2
    exit 1
fi

# shellcheck source=config.sh disable=SC1091
source "${CONFIG_FILE}"

# shellcheck source=lib/libprovision.sh
source "${LIB_DIR}/libprovision.sh"

assert_env_vars RELEASE VM_NAME_BASE

ARTIFACTS_DIR="${SCRIPT_DIR}/.artifacts/${RELEASE}"

if [ -z "${VM_NAME:-}" ]; then
    VM_NAME="${VM_NAME_BASE}-${RELEASE}"
fi

# Print executed commands to ease debugging
set -x

# Check if we have all required artifacts
IMAGE="${ARTIFACTS_DIR}/${VM_NAME_BASE}.qcow2"
if [ ! -f "${IMAGE}" ]; then
    echo "Image not found: ${IMAGE}. Please run e2e-tests/vm/provision-ubuntu.sh first."
    exit 1
fi

LIBVIRT_XML="${ARTIFACTS_DIR}/${VM_NAME_BASE}.xml"
if [ ! -f "${LIBVIRT_XML}" ]; then
    echo "Libvirt XML file not found: ${LIBVIRT_XML}. Please run e2e-tests/vm/provision-ubuntu.sh first."
    exit 1
fi

# shellcheck source=lib/libprovision.sh
source "${LIB_DIR}/libprovision.sh"

# Define the VM
if ! virsh dominfo "${VM_NAME}" &> /dev/null; then
    virsh define "${LIBVIRT_XML}"
fi

# Boot the VM if not running
if ! virsh domstate "${VM_NAME}" | grep -q '^running'; then
    boot_system
fi

# Create snapshot initial setup if it doesn't exist
if ! has_snapshot "initial-setup"; then
    force_create_snapshot "initial-setup"
fi

# Install authd stable and create a snapshot
retry --times 3 --delay 1 -- timeout 30 -- "$SSH" -- \
  "sudo add-apt-repository -y ppa:ubuntu-enterprise-desktop/authd"

timeout 600 -- \
    "$SSH" -- \
    'sudo apt-get install -y authd && \
     sudo mkdir -p /etc/systemd/system/authd.service.d && \
     cat <<-EOF | sudo tee /etc/systemd/system/authd.service.d/override.conf
		[Service]
		ExecStart=
		ExecStart=/usr/libexec/authd -vv
		EOF'

force_create_snapshot "authd-stable-installed"

# Revert to the initial setup snapshot before installing authd edge
restore_snapshot_and_sync_time "initial-setup"

# Install authd edge and create a snapshot
retry --times 3 --delay 1 -- timeout 30 -- "$SSH" -- \
  "sudo add-apt-repository -y ppa:ubuntu-enterprise-desktop/authd-edge"

timeout 600 -- \
    "$SSH" -- \
    'sudo apt-get install -y authd && \
     sudo mkdir -p /etc/systemd/system/authd.service.d && \
     cat <<-EOF | sudo tee /etc/systemd/system/authd.service.d/override.conf
		[Service]
		ExecStart=
		ExecStart=/usr/libexec/authd -vv
		EOF'

force_create_snapshot "authd-edge-installed"
