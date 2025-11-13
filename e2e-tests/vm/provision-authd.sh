#!/usr/bin/env bash

set -euo pipefail

usage(){
    cat << EOF
Usage: $0 --ssh-public-key <file> --issuer-id <id> --client-id <id> --user <name>
       $0 -k <file> -i <id> -c <id> -u <name>

Options:
  -k, --ssh-public-key <file>   Path to the SSH public key file to be added to the VM
  -i, --issuer-id <id>          OIDC Issuer ID for broker configuration
  -c, --client-id <id>          OIDC Client ID for broker configuration
  -u, --user <name>             Username used for authd login in the tests
  -h, --help                    Show this help message and exit

Provisions authd in the VM for end-to-end tests
EOF
}

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
LIBVIRT_XML_TEMPLATE="${SCRIPT_DIR}/e2e-runner-template.xml"
ARTIFACTS_DIR="${SCRIPT_DIR}/.artifacts"
SSH="${SCRIPT_DIR}/ssh.sh"

VM_NAME="e2e-runner"
BROKERS=("authd-msentraid")

while [[ $# -gt 0 ]]; do
    case "$1" in
        -k|--ssh-public-key)
            SSH_PUBLIC_KEY_FILE="$2"
            shift 2
            ;;
        -i|--issuer-id)
            ISSUER_ID="$2"
            shift 2
            ;;
        -c|--client-id)
            CLIENT_ID="$2"
            shift 2
            ;;
        -u|--user)
            AUTHD_USER="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        --)
            shift
            break
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

if [ -z "${SSH_PUBLIC_KEY_FILE:-}" ] || \
   [ -z "${ISSUER_ID:-}" ] || \
   [ -z "${CLIENT_ID:-}" ] || \
   [ -z "${AUTHD_USER:-}" ]; then
   echo "Missing required arguments." >&2
   usage
   exit 1
fi

# Validate SSH public key file
if [ ! -f "${SSH_PUBLIC_KEY_FILE}" ]; then
    echo "SSH public key file not found: ${SSH_PUBLIC_KEY_FILE}"
    exit 1
fi

if [[ "${SSH_PUBLIC_KEY_FILE}" != *.pub ]]; then
    echo "SSH public key file must have a .pub extension"
    exit 1
fi

function force_create_snapshot() {
    local snapshot_name="$1"
    if virsh snapshot-list "${VM_NAME}" | grep -q "${snapshot_name}"; then
        time virsh snapshot-delete --domain "${VM_NAME}" --snapshotname "${snapshot_name}"
    fi

    if virsh domstate "${VM_NAME}" | grep -q '^running'; then
        # If the VM is running, we have to use --memspec to create the snapshot
        memfile="${IMAGE%.qcow2}-${snapshot_name}.mem"
        time virsh snapshot-create-as --domain "${VM_NAME}" --name "${snapshot_name}" \
          --memspec "${memfile},snapshot=external"
        return
    fi

    time virsh snapshot-create-as --domain "${VM_NAME}" --name "${snapshot_name}" --disk-only
}

function wait_for_system_running() {
    # shellcheck disable=SC2016
    local cmd='output=$(systemctl is-system-running --wait) || [ $output = degraded ]'
    retry --times 30 --delay 3 -- "$SSH" "$cmd"
}

function install_brokers() {
    local channel="$1"
    local base_snapshot="authd-${channel}-installed"
    local broker

    for broker in "${BROKERS[@]}"; do
        local broker_config="${broker#authd-}.conf"

        # Install broker, configure and restart services
        $SSH bash -euo pipefail -s <<-EOF
			sudo snap install "${broker}" --channel="${channel}"
			sudo mkdir -p /etc/authd/brokers.d
			sudo cp /snap/${broker}/current/conf/authd/${broker_config} /etc/authd/brokers.d/
			sudo sed -i \
		  		-e "s|<ISSUER_ID>|${ISSUER_ID}|g" \
		  		-e "s|<CLIENT_ID>|${CLIENT_ID}|g" \
		  		-e "s|#ssh_allowed_suffixes_first_auth =|ssh_allowed_suffixes_first_auth = ${AUTHD_USER}|g" \
		  		/var/snap/${broker}/current/broker.conf
			echo 'verbosity: 2' | sudo tee /var/snap/authd-msentraid/current/${broker}.yaml
			sudo systemctl restart authd.service
			sudo snap restart "${broker}"
		EOF

        # Reboot VM and wait until it's back
        virsh reboot "${VM_NAME}"
        wait_for_system_running

        # Snapshot this broker installation
        force_create_snapshot "${broker}-${channel}-configured"

        # If not the last broker, revert to the base authd snapshot for this channel
        if [ "${broker}" != "${BROKERS[-1]}" ]; then
            virsh snapshot-revert "${VM_NAME}" --snapshotname "${base_snapshot}"
        fi
    done
}

# Print executed commands to ease debugging
set -x

# Install required packages
sudo apt-get -y install \
    bsdutils \
    clang \
    ffmpeg \
    gir1.2-webkit2-4.1 \
    libcairo2-dev \
    libgirepository-2.0-dev \
    libvirt0 \
    libvirt-clients \
    libvirt-clients-qemu \
    libvirt-daemon \
    libvirt-daemon-driver-qemu \
    libvirt-daemon-system \
    libxkbcommon-dev \
    qemu-kvm \
    qemu-system-x86 \
    qemu-utils \
    python3-cairo \
    python3-gi \
    python3-tk \
    socat \
    xvfb


# Copy and resize the image
IMAGE="${ARTIFACTS_DIR}/e2e-runner.qcow2"
if [ ! -f "${IMAGE}" ]; then
    echo "Image not found: ${IMAGE}. Please run e2e-tests/vm/provision-ubuntu.sh first."
    exit 1
fi

# Create the libvirt XML
LIBVIRT_XML="${ARTIFACTS_DIR}/e2e-runner.xml"
if [ ! -f "${LIBVIRT_XML}" ]; then
    IMAGE_FILE=${IMAGE} \
      envsubst < "${LIBVIRT_XML_TEMPLATE}" > "${LIBVIRT_XML}"
else
    echo "Libvirt XML file already exists: ${LIBVIRT_XML}"
fi

# Define the VM
if ! virsh dominfo "${VM_NAME}" &> /dev/null; then
    virsh define "${LIBVIRT_XML}"
else
    echo "VM already defined: ${VM_NAME}"
fi


# Boot the VM and wait until it's running
virsh start "${VM_NAME}"
wait_for_system_running

# Create a snapshot of the initial setup
force_create_snapshot "initial-setup"

# Install authd stable and create a snapshot
$SSH "sudo add-apt-repository -y ppa:ubuntu-enterprise-desktop/authd && \
      sudo apt-get install -y authd && \
      sudo mkdir -p /etc/systemd/system/authd.service.d && \
      cat <<-EOF | sudo tee /etc/systemd/system/authd.service.d/override.conf
		[Service]
		ExecStart=
		ExecStart=/usr/libexec/authd -vv
		EOF"
force_create_snapshot "authd-stable-installed"

install_brokers "stable"

# Remove the authd-stable-installed snapshot which is no longer needed
virsh snapshot-delete --domain "${VM_NAME}" --snapshotname "authd-stable-installed"

# Revert to the initial setup snapshot before installing authd edge
virsh snapshot-revert "${VM_NAME}" --snapshotname "initial-setup"

# Install authd edge and create a snapshot
$SSH "sudo add-apt-repository -y ppa:ubuntu-enterprise-desktop/authd-edge && \
      sudo apt-get install -y authd && \
      sudo mkdir -p /etc/systemd/system/authd.service.d && \
      cat <<-EOF | sudo tee /etc/systemd/system/authd.service.d/override.conf
		[Service]
		ExecStart=
		ExecStart=/usr/libexec/authd -vv
		EOF"
force_create_snapshot "authd-edge-installed"

install_brokers "edge"

# Remove the authd-edge-installed snapshot which is no longer needed
virsh snapshot-delete --domain "${VM_NAME}" --snapshotname "authd-edge-installed"
