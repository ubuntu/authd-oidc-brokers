#!/usr/bin/env bash

set -euo pipefail

usage(){
    cat << EOF
Usage: $0 --ssh-public-key <file>
       $0 -k <file>

Options:
  -k, --ssh-public-key <file>   Path to the SSH public key file to be added to the VM
  -h, --help                    Show this help message and exit

Provisions the VM for end-to-end tests
EOF
}

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
CLOUD_INIT_TEMPLATE="${SCRIPT_DIR}/cloud-init-template.yaml"
LIBVIRT_XML_TEMPLATE="${SCRIPT_DIR}/e2e-runner-template.xml"
CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/authd-e2e-tests"
ARTIFACTS_DIR="${SCRIPT_DIR}/.artifacts"

VM_NAME="e2e-runner"

if [ -f "${SCRIPT_DIR}/.aliases" ]; then
    source "${SCRIPT_DIR}/.aliases"
fi

# Installing all the packages can take some time, so we set the timeout to 15 minutes
CLOUT_INIT_TIMEOUT=900

while [[ $# -gt 0 ]]; do
    case "$1" in
        -k|--ssh-public-key)
            SSH_PUBLIC_KEY_FILE="$2"
            shift 2
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

if [ -z "${SSH_PUBLIC_KEY_FILE:-}" ]; then
   echo "Missing required argument." >&2
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

# Print executed commands to ease debugging
set -x

# Install required packages
sudo apt-get -y install \
    bsdutils \
    cloud-image-utils \
    libvirt0 \
    libvirt-clients \
    libvirt-clients-qemu \
    libvirt-daemon \
    libvirt-daemon-driver-qemu \
    libvirt-daemon-system \
    qemu-kvm \
    qemu-system-x86 \
    qemu-utils \
    sshpass \
    wget \
    xvfb

# Download the image
IMAGE_URL="https://cloud-images.ubuntu.com/questing/current/questing-server-cloudimg-amd64.img"
SOURCE_IMAGE="${CACHE_DIR}/questing-server-cloudimg-amd64.img"
if [ ! -f "${SOURCE_IMAGE}" ]; then
    mkdir -p "${CACHE_DIR}"
    wget -O "${SOURCE_IMAGE}" "${IMAGE_URL}"
else
    echo "Source image already exists: ${SOURCE_IMAGE}"
fi

# Copy and resize the image
IMAGE="${ARTIFACTS_DIR}/e2e-runner.qcow2"
if [ ! -f "${IMAGE}" ]; then
    mkdir -p "${ARTIFACTS_DIR}"
    cp "${SOURCE_IMAGE}" "${IMAGE}"

    qemu-img resize "${IMAGE}" 10G
    sudo chown libvirt-qemu:kvm "${IMAGE}"
else
    echo "Image already exists: ${IMAGE}"
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
if ! cloud_init_finished "${IMAGE}"; then
    # Start the VM to let cloud-init do its work
    virsh start "${VM_NAME}"

    # Print the console output and wait until cloud-init has finished and the VM has shut down
    echo "Waiting for VM to finish cloud-init setup..."
    script -q -e -f /dev/null -c "virsh console $VM_NAME" &
    VM_CONSOLE_PID=$!
    virsh await "${VM_NAME}" --condition domain-inactive --timeout "${CLOUT_INIT_TIMEOUT}"
    kill "${VM_CONSOLE_PID}" || true

    # Detach the cloud-init iSO
    virsh detach-disk "${VM_NAME}" sda --config
fi

