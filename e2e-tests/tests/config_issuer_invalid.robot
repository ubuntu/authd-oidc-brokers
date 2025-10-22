*** Settings ***
Resource        ${AUTHD_RESOURCES_DIR}/utils.resource
Resource        ${AUTHD_RESOURCES_DIR}/authd.resource

Resource        ${BROKER_RESOURCES_DIR}/broker.resource

Test Tags       robot:exit-on-failure


*** Variables ***
${AUTHD_RESOURCES_DIR}        ${CURDIR}/authd-resources
${BROKER_RESOURCES_DIR}      ${CURDIR}/broker-resources

${username}    %{E2E_USER}
${local_password}    qwer1234


*** Test Cases ***
Log in with local user
    Log in


Change Broker Configuration to an invalid issuer
    Change Broker Configuration    issuer    invalid


Try to log in with remote user when broker has invalid issuer
    Open Terminal
    Start Log In With Remote User Through CLI: QR Code    ${username}
    Select Provider
    Check That Remote User Has No Available Authentication Modes
