*** Settings ***
Resource        ${AUTHD_RESOURCES_DIR}/utils.resource
Resource        ${AUTHD_RESOURCES_DIR}/authd.resource

Resource        ${BROKER_RESOURCES_DIR}/broker.resource

Test Tags       robot:exit-on-failure


*** Variables ***
${AUTHD_RESOURCES_DIR}        ${CURDIR}/authd-resources
${BROKER_RESOURCES_DIR}      ${CURDIR}/broker-resources

${username}    another-%{E2E_USER}
${local_password}    qwer1234
${remote_group}    %{E2E_USER}-group


*** Test Cases ***
Log in with local user
    Log in


Try to log in with not allowed remote user with device authentication through SSH
    Open Terminal
    Start Log In With Remote User Through SSH: QR Code    ${username}
    Select Provider through SSH
    Continue Log In With Remote User: Log In On External Browser    ${username}
    Continue Log In With Remote User Through SSH: QR Code
    Check That Remote User Is Not Allowed To Log In
