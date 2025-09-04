#!/bin/bash

set -eu

# This script is used to run the YARF tests for the authd-oidc-brokers project.
ROOT_DIR=$(dirname "$(readlink -f "$0")")
VM_DIR="${ROOT_DIR}/vm"
TESTS_DIR="${ROOT_DIR}/tests"
AUTHD_COMMON_DIR="${ROOT_DIR}/common"
BROKER_COMMON_DIR="${ROOT_DIR}/$BROKER/common"

# Create directory for the test run
TEST_RUN_DIR="/tmp/oidc-e2e-test-run"
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

    echo "Resetting VM snapshots..."
    ${VM_DIR}/reset-snapshots.sh

    VM_IMG=authd-edge
    if [[ "${test_name}" == *"migration"* ]]; then
        VM_IMG=authd-stable
    fi
    echo "Using VM image: ${VM_IMG}"

    echo "Spawning VM with snapshot: ${VM_IMG}"
    ${VM_DIR}/spawn-vm.sh ${VM_IMG} &
    sleep 5  # Wait a bit for the VM to boot up
    VM_PID=$(pidof kvm)
    echo "VM PID: ${VM_PID}"

    TEST_PASSWORD="$REMOTE_PASSWORD" yarf --outdir "output/${test_name}" --platform=Vnc . || true
    test_result=$?

    if [ -n "${KEEP_VM:-}" ]; then
        echo "Stopping the test run and keeping VM running as requested: ${VM_PID}."
        exit ${test_result}
    else
        echo "Stopping VM: ${VM_PID}"
        kill -KILL "${VM_PID}"
    fi

    sleep 5  # Wait for the VM to stop
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
