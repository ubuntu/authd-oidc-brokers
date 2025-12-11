#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
LIB_DIR="${SCRIPT_DIR}/lib"
SSH="${SCRIPT_DIR}/ssh.sh"
CONFIG_FILE="${SCRIPT_DIR}/config.sh"

usage(){
    cat << EOF
Usage: $0 --broker <name> [--config-file <file>] [--delete-snapshots]

Options:
  -b, --broker <name>           Name of the broker to install (e.g., authd-msentraid)
  --config-file <file>          Path to the configuration file (default: config.sh)
  --delete-snapshots            Delete intermediate snapshots after provisioning
  -h, --help                    Show this help message and exit

Provisions the specified broker in the VM for end-to-end tests
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -b|--broker)
            BROKER="$2"
            shift 2
            ;;
        --config-file)
            CONFIG_FILE="$2"
            shift 2
            ;;
        --delete-snapshots)
            DELETE_SNAPSHOTS=true
            shift
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

# shellcheck source=config.sh disable=SC1091
source "${CONFIG_FILE}"

if [ -z "${BROKER:-}" ]; then
    echo "Broker name is required. Use --broker <name> to specify it."
    exit 1
fi

# shellcheck source=lib/libprovision.sh
source "${LIB_DIR}/libprovision.sh"

assert_env_vars VM_NAME_BASE RELEASE

ARTIFACTS_DIR="${SCRIPT_DIR}/.artifacts/${RELEASE}"

if [ -z "${VM_NAME:-}" ]; then
    VM_NAME="${VM_NAME_BASE}-${RELEASE}"
fi

function install_broker() {
    local channel="$1"
    local base_snapshot="authd-${channel}-installed"
    local broker_config="${BROKER#authd-}.conf"

    # Get the issuer ID from the environment variable corresponding to the broker.
    # For example, for broker "authd-msentraid", we use "AUTHD_MSENTRAID_ISSUER_ID".
    local broker_prefix="${BROKER^^}"
    broker_prefix="${broker_prefix//-/_}"
    local issuer_id_var="${broker_prefix}_ISSUER_ID"
    local issuer_id="${!issuer_id_var}"
    local client_id_var="${broker_prefix}_CLIENT_ID"
    local client_id="${!client_id_var}"
    local client_secret_var="${broker_prefix}_CLIENT_SECRET"
    local client_secret="${!client_secret_var:-}"

    virsh snapshot-revert "${VM_NAME}" --snapshotname "${base_snapshot}"

    # Install broker, configure and restart services
    $SSH bash -euo pipefail -s <<-EOF
        sudo snap install "${BROKER}" --channel="${channel}"
        sudo mkdir -p /etc/authd/brokers.d
        sudo cp /snap/${BROKER}/current/conf/authd/${broker_config} /etc/authd/brokers.d/
        sudo sed -i \
            -e "s|<ISSUER_ID>|${issuer_id}|g" \
            -e "s|<CLIENT_ID>|${client_id}|g" \
			-e "s|<CLIENT_SECRET>|${client_secret}|g" \
            /var/snap/${BROKER}/current/broker.conf
        echo 'verbosity: 2' | sudo tee /var/snap/${BROKER}/current/${BROKER}.yaml
        sudo systemctl restart authd.service
        sudo snap restart "${BROKER}"
	EOF

    # Reboot VM and wait until it's back
    virsh reboot "${VM_NAME}"
    wait_for_system_running

    # Snapshot this broker installation
    force_create_snapshot "${BROKER}-${channel}-configured"
}

# Print executed commands to ease debugging
set -x

IMAGE="${ARTIFACTS_DIR}/${VM_NAME_BASE}.qcow2"
if [ ! -f "${IMAGE}" ]; then
    echo "Image not found: ${IMAGE}. Please run e2e-tests/vm/provision-ubuntu.sh first."
    exit 1
fi

# Check if the VM is already defined
if ! virsh dominfo "${VM_NAME}" &> /dev/null; then
    echo "Domain not found: ${VM_NAME}. Please run provision-ubuntu.sh or provision-authd.sh first."
    exit 1
fi

install_broker "stable"
# Remove the authd-stable-installed snapshot which is no longer needed
if [ ! -z "${DELETE_SNAPSHOTS:-}" ]; then
	virsh snapshot-delete --domain "${VM_NAME}" --snapshotname "authd-stable-installed"
fi

install_broker "edge"
# Remove the authd-edge-installed snapshot which is no longer needed
if [ ! -z "${DELETE_SNAPSHOTS:-}" ]; then
	virsh snapshot-delete --domain "${VM_NAME}" --snapshotname "authd-edge-installed"
fi
