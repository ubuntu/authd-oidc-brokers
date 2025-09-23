*** Settings ***
Resource        ${AUTHD_COMMON_DIR}/utils.resource
Resource        ${AUTHD_COMMON_DIR}/authd.resource

Resource        ${BROKER_COMMON_DIR}/broker.resource

Test Tags       robot:exit-on-failure


*** Variables ***
${AUTHD_COMMON_DIR}        ${CURDIR}/authd-common
${BROKER_COMMON_DIR}      ${CURDIR}/broker-common

${username}    %{E2E_USER}
${local_password}    qwer1234
${remote_group}    %{E2E_USER}-group


*** Test Cases ***
Log in with local user
    Log in


Log in with remote user with device authentication through SSH
    Open GNOME Terminal
    Log In With Remote User Through SSH: QR Code    ${username}    ${local_password}
    Close GNOME Terminal In Sudo Mode


Check remote user is properly added to the system
    Open GNOME Terminal
    Get NSS Passwd Entry For Remote User    ${username}
    Check User Information    ${username}
    Get NSS Group Entries For Remote User    ${username}
    Check User Groups    ${username}    ${remote_group}
    Close Focused Window


Log in with remote user with local password through SSH
    Open GNOME Terminal
    Log In With Remote User Through SSH: Local Password    ${username}    ${local_password}
    Check That Remote User Can Run Sudo Commands    ${local_password}
