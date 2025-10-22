*** Settings ***
Resource        ${AUTHD_RESOURCES_DIR}/utils.resource
Resource        ${AUTHD_RESOURCES_DIR}/authd.resource

Resource        ${BROKER_RESOURCES_DIR}/broker.resource

Test Tags       robot:exit-on-failure


*** Variables ***
${AUTHD_RESOURCES_DIR}        ${CURDIR}/authd-resources
${BROKER_RESOURCES_DIR}      ${CURDIR}/broker-resources

${username}    %{E2E_USER}


*** Test Cases ***
Log in with local user
    Log in


Disable authd
    Disable Authd Socket and Service


Ensure local sudo user can still log in
    Open Terminal
    Enter Sudo Mode In Terminal
    Close Terminal In Sudo Mode


Check that remote user can't log in
    Open Terminal In Sudo Mode
    Try Log In With Remote User    ${username}
    Check That Log In Fails Because Authd Is Disabled
    Cancel Operation
    Close Terminal In Sudo Mode
