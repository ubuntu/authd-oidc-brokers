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

# Provision the VM with Ubuntu
"${SCRIPT_DIR}/provision-ubuntu.sh" --ssh-public-key "${SSH_PUBLIC_KEY_FILE}"

# Provision authd in the VM
"${SCRIPT_DIR}/provision-authd.sh" \
    --ssh-public-key "${SSH_PUBLIC_KEY_FILE}" \
    --issuer-id "${ISSUER_ID}" \
    --client-id "${CLIENT_ID}" \
    --user "${AUTHD_USER}"

echo "Provisioning completed successfully."