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
${new_password}    passwd1234
${remote_group}    %{E2E_USER}-group


*** Test Cases ***
Log in with local user
    Log in


Log in with remote user with device authentication
    Open GNOME Terminal
    Log In With Remote User Through CLI: QR Code    ${username}    ${domain}    ${local_password}


Change Local Password Of Remote User
    Open GNOME Terminal In Sudo Mode
    Change Local Password Of Remote User    ${username}    ${domain}    ${local_password}    ${new_password}
    Close GNOME Terminal In Sudo Mode


Log in with remote user with local password
    Open GNOME Terminal In Sudo Mode
    Log In With Remote User Through CLI: Local Password    ${username}    ${domain}    ${new_password}
