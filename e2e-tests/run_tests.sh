#!/usr/bin/env bash

set -eu

# Required environment variables:
#    E2E_USER - The username to use for the tests
#    E2E_PASSWORD - The password to use for the tests
#    BROKER - The broker to test (e.g., authd-msentraid)
# Optional environment variables:
#    SNAPSHOT_ON_FAIL - If set, a snapshot of the VM will be taken if a test fails.
#    RUN_ONSCREEN - If set to 1, the additional window for remote authentication will be run onscreen (useful for debugging)

# Required setup:
#   Virsh domain named 'e2e-runner' must exist
#   Domain snapshots created:
#      ${broker}-stable-configured
#      ${broker}-edge-configured

# This script is used to run the YARF tests for the authd-oidc-brokers project.
ROOT_DIR=$(dirname "$(readlink -f "$0")")
TESTS_DIR="${ROOT_DIR}/tests"
AUTHD_COMMON_DIR="${ROOT_DIR}/common"
BROKER_COMMON_DIR="${ROOT_DIR}/$BROKER/common"

# Create directory for the test run
TEST_RUN_DIR="/tmp/e2e-testrun-${BROKER}"
mkdir -p "${TEST_RUN_DIR}"
cd "${TEST_RUN_DIR}"

# Link the necessary directories into the test run directory if they don't already exist
[ -d authd-common ] || [ -L authd-common ] && rm -rf authd-common
[ -d broker-common ] || [ -L broker-common ] && rm -rf broker-common
ln -s "${AUTHD_COMMON_DIR}" authd-common
ln -s "${BROKER_COMMON_DIR}" broker-common
mkdir -p output

# Read entire tests dir if arguments are not provided
TESTS_TO_RUN="${TESTS_DIR}/*.robot"
if [ -n "${1:-}" ]; then
    echo "Running specific test: ${1}"
    TESTS_TO_RUN="${TESTS_DIR}/$(basename "${1}")"
fi

# Run the YARF tests
test_results=()
for test_file in $TESTS_TO_RUN; do
    ln -s "${test_file}" .

    test_name=$(basename "${test_file}")
    echo "Running test: ${test_name}"

    SNAPSHOT_NAME=${BROKER}-edge-configured
    if [[ "${test_name}" == *"migration"* ]]; then
        SNAPSHOT_NAME=${BROKER}-stable-configured
    fi

    virsh snapshot-revert e2e-runner "${SNAPSHOT_NAME}" || true

    # Temporarily allow a command that could error out so we can grab the test result.
    set +e
    E2E_USER="$E2E_USER" \
    E2E_PASSWORD="$E2E_PASSWORD" \
    yarf --outdir "output/${test_name}" --platform=Vnc .
    test_result=$?

    set -e
    if [ ${test_result} -ne 0 ] && [ -v SNAPSHOT_ON_FAIL ]; then
        echo "Test failed. Saving VM snapshot as requested..."
        virsh snapshot-create-as e2e-runner "${test_name}-fail-$(date +%Y%m%d%H%M)"
        echo "Snapshot '${test_name}-fail-$(date +%Y%m%d%H%M)' created."
    fi

    if [ ${test_result} -ne 0 ]; then
        test_results+=("${test_name}: FAILED")
    else
        test_results+=("${test_name}: OK")
    fi
    rm "${test_name}"
done

for result in "${test_results[@]}"; do
    echo "${result}"
done
