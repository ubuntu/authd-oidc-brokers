*** Settings ***
Resource        ${AUTHD_COMMON_DIR}/utils.resource
Resource        ${AUTHD_COMMON_DIR}/authd.resource

Resource        ${BROKER_COMMON_DIR}/broker.resource

Test Tags       robot:exit-on-failure


*** Variables ***
${AUTHD_COMMON_DIR}        ${CURDIR}/authd-common
${BROKER_COMMON_DIR}      ${CURDIR}/broker-common

${username}    another-%{E2E_USER}


*** Test Cases ***
Log in with local user
    Log in


Log in with remote user with device authentication
    Open Terminal
    Start Log In With Remote User Through CLI: QR Code    ${username}
    Select Provider
    Continue Log In With Remote User: Log In On External Browser    ${username}
    Check That Remote User Is Not Allowed To Log In
