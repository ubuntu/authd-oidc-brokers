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


*** Test Cases ***
Log in with local user
    Log in


Disable broker
    Disable Broker And Purge Config


Ensure local sudo user can still log in
    Open GNOME Terminal
    Enter Sudo Mode In GNOME Terminal
    Close GNOME Terminal In Sudo Mode


Check that remote user can't log in
    Open GNOME Terminal In Sudo Mode
    Try Log In With Remote User    ${username}    ${domain}
    Check That User Is Redirected To Local Broker
    Cancel Operation
    Close GNOME Terminal In Sudo Mode
