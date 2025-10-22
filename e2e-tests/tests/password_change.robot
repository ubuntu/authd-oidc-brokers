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
${new_password}    passwd1234
${remote_group}    %{E2E_USER}-group


*** Test Cases ***
Log in with local user
    Log in


Log in with remote user with device authentication
    Open Terminal
    Log In With Remote User Through CLI: QR Code    ${username}    ${local_password}
    Log Out From Terminal Session
    Close Focused Window


Change Local Password Of Remote User
    Open Terminal In Sudo Mode
    Change Local Password Of Remote User    ${username}    ${local_password}    ${new_password}
    Close Terminal In Sudo Mode


Log in with remote user with local password
    Open Terminal In Sudo Mode
    Log In With Remote User Through CLI: Local Password    ${username}    ${new_password}
