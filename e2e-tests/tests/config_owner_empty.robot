*** Settings ***
Resource        ${AUTHD_COMMON_DIR}/utils.resource
Resource        ${AUTHD_COMMON_DIR}/authd.resource

Resource        ${BROKER_COMMON_DIR}/broker.resource

Test Tags       robot:exit-on-failure


*** Variables ***
${AUTHD_COMMON_DIR}        ${CURDIR}/authd-common
${BROKER_COMMON_DIR}      ${CURDIR}/broker-common

${username}    %{E2E_USER}
${domain}      %{E2E_DOMAIN}
${local_password}    qwer1234


*** Test Cases ***
Log in with local user
    Log in


Change Broker Configuration to allowed_users as OWNER only
    Comment Key In Broker Configuration    owner
    Change allowed_users In Broker Configuration    OWNER


Log in with remote user with QR code
    Open GNOME Terminal
    Log In With Remote User Through CLI: QR Code    ${username}    ${domain}    ${local_password}
    Log Out From Terminal Session
    Close Focused Window


Log in with remote user with local password
    Open GNOME Terminal In Sudo Mode
    Log In With Remote User Through CLI: Local Password    ${username}    ${domain}    ${local_password}
    Log Out From Terminal Session
    Close GNOME Terminal In Sudo Mode


Check That owner Was Updated In Broker Configuration
    Open GNOME Terminal In Sudo Mode
    Check If Owner Was Registered    %{E2E_USER}@%{E2E_DOMAIN}
