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

Provisions the VM for end-to-end tests
EOF
}

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
CLOUD_INIT_TEMPLATE="${SCRIPT_DIR}/cloud-init-template.yaml"
LIBVIRT_XML_TEMPLATE="${SCRIPT_DIR}/e2e-runner-template.xml"
ARTIFACTS_DIR="${SCRIPT_DIR}/.artifacts"
SSH="${SCRIPT_DIR}/ssh.sh"

VM_NAME="e2e-runner"
BROKERS=("authd-msentraid")

# Installing all the packages can take some time, so we set the timeout to 15 minutes
CLOUT_INIT_TIMEOUT=900

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

function cloud_init_finished() {
    local image=$1
    sudo guestfish --ro -a "${image}" -i stat /var/lib/cloud/instance/boot-finished &>/dev/null
}

function force_create_snapshot() {
    local snapshot_name="$1"
    if virsh snapshot-list "${VM_NAME}" | grep -q "${snapshot_name}"; then
        virsh snapshot-delete --domain "${VM_NAME}" --snapshotname "${snapshot_name}"
    fi
    virsh snapshot-create-as --domain "${VM_NAME}" "${snapshot_name}" --reuse-external
}

function wait_for_system_running() {
    retry --times 20 --delay 3 -- "$SSH" "systemctl is-system-running --wait"
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
    cloud-image-utils \
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
    sshpass \
    wget \
    xvfb

# Download the image
mkdir -p "${ARTIFACTS_DIR}"
IMAGE_URL="https://cloud-images.ubuntu.com/questing/current/questing-server-cloudimg-amd64.img"
IMAGE_FILE="${ARTIFACTS_DIR}/questing-server-cloudimg-amd64.img"
if [ ! -f "${IMAGE_FILE}" ]; then
    wget -O "${IMAGE_FILE}" "${IMAGE_URL}"
else
    echo "Image file already exists: ${IMAGE_FILE}"
fi

# Copy and resize the image
IMAGE_FILE_ORIG="${IMAGE_FILE}"
IMAGE_FILE="${ARTIFACTS_DIR}/e2e-runner.qcow2"
if [ ! -f "${IMAGE_FILE}" ]; then
    # Copy the image to avoid modifying the original
    cp "${IMAGE_FILE_ORIG}" "${IMAGE_FILE}"

    # Resize the image to 10GB
    qemu-img resize "${IMAGE_FILE}" 10G
else
    echo "Copied image file already exists: ${IMAGE_FILE}"
fi

# Create a cloud-init ISO
CLOUD_INIT_ISO="${ARTIFACTS_DIR}/seed.iso"
if [ ! -f "${CLOUD_INIT_ISO}" ]; then
    CLOUD_INIT_DIR="$(mktemp -d)"
    trap 'rm -rf ${CLOUD_INIT_DIR}' EXIT

    SSH_PUBLIC_KEY=$(cat "${SSH_PUBLIC_KEY_FILE}") \
        envsubst < "${CLOUD_INIT_TEMPLATE}" > "${CLOUD_INIT_DIR}/user-data"

    cloud-localds "${CLOUD_INIT_ISO}" "${CLOUD_INIT_DIR}/user-data"
else
    echo "Cloud-init ISO already exists: ${CLOUD_INIT_ISO}"
fi

# Create the libvirt XML
LIBVIRT_XML="${ARTIFACTS_DIR}/e2e-runner.xml"
if [ ! -f "${LIBVIRT_XML}" ]; then
    IMAGE_FILE=${IMAGE_FILE} \
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

# Attach the cloud-init ISO
if ! virsh domblklist "${VM_NAME}" | grep -q "seed.iso"; then
    virsh attach-disk "${VM_NAME}" "${CLOUD_INIT_ISO}" sda --type cdrom --mode readonly --config
else
    echo "Cloud-init ISO already attached to VM: ${VM_NAME}"
fi

# Ensure the VM is shut off before proceeding
if virsh domstate "${VM_NAME}" | grep -q '^running'; then
    virsh destroy "${VM_NAME}"
fi

# Start the VM and wait for it to finish the initial setup
if ! cloud_init_finished "${IMAGE_FILE}"; then
    # Start the VM to let cloud-init do its work
    virsh start "${VM_NAME}"

    # Print the console output and wait until cloud-init has finished and the VM has shut down
    echo "Waiting for VM to finish cloud-init setup..."
    script -q -e -f /dev/null -c "virsh console $VM_NAME" &
    VM_CONSOLE_PID=$!
    virsh await "${VM_NAME}" --condition domain-inactive --timeout "${CLOUT_INIT_TIMEOUT}"
    kill "${VM_CONSOLE_PID}" || true

    # Boot the VM and wait until it's running
    virsh start "${VM_NAME}"
    wait_for_system_running

    # Create a snapshot of the initial setup
    force_create_snapshot "initial-setup"
else
    echo "Cloud-init has already finished."
    virsh snapshot-revert "${VM_NAME}" --snapshotname "initial-setup"
fi

# Install authd stable and create a snapshot
$SSH "sudo add-apt-repository -y ppa:ubuntu-enterprise-desktop/authd && \
      sudo apt-get install -y authd"
force_create_snapshot "authd-stable-installed"

install_brokers "stable"

# Revert to the initial setup snapshot before installing authd edge
virsh snapshot-revert "${VM_NAME}" --snapshotname "initial-setup"

# Install authd edge and create a snapshot
$SSH "sudo add-apt-repository -y ppa:ubuntu-enterprise-desktop/authd-edge && \
      sudo apt-get install -y authd"
force_create_snapshot "authd-edge-installed"

install_brokers "edge"
