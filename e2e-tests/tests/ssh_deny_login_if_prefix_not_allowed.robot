*** Settings ***
Resource        ${AUTHD_COMMON_DIR}/utils.resource
Resource        ${AUTHD_COMMON_DIR}/authd.resource

Resource        ${BROKER_COMMON_DIR}/broker.resource

Test Tags       robot:exit-on-failure


*** Variables ***
${AUTHD_COMMON_DIR}        ${CURDIR}/authd-common
${BROKER_COMMON_DIR}      ${CURDIR}/broker-common

${username}    another-%{E2E_USER}
${domain}      %{E2E_DOMAIN}
${local_password}    qwer1234
${remote_group}    %{E2E_USER}-group


*** Test Cases ***
Log in with local user
    Log in


Try to log in with not allowed remote user with device authentication through SSH
    Open GNOME Terminal
    Start Log In With Remote User Through SSH: QR Code    ${username}    ${domain}
    Select Provider through SSH
    Continue Log In With Remote User: Log In On Browser    ${username}    ${domain}
    Continue Log In With Remote User Through SSH: QR Code
    Check That Remote User Is Not Allowed To Log In
