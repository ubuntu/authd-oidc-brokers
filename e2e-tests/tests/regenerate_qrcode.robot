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
${remote_group}    %{E2E_USER}-group


*** Test Cases ***
Log in with local user
    Log in


Log in with remote user with device authentication
    Open GNOME Terminal
    Start Log In With Remote User Through CLI: QR Code   ${username}    ${domain}
    Select Provider
    # Let's try regenerating the QR code a couple of times
    Regenerate QR Code
    Regenerate QR Code
    Regenerate QR Code
    # Now we should be able to log in with the remote user using the latest QR code
    Continue Log In With Remote User: Log In On Browser   ${username}    ${domain}
    Continue Log In With Remote User Through CLI: Define Local Password   ${username}    ${domain}    ${local_password}


Check remote user is properly added to the system
    Open GNOME Terminal
    Get NSS Passwd Entry For Remote User    ${username}    ${domain}
    Check User Information    ${username}    ${domain}
    Get NSS Group Entries For Remote User    ${username}    ${domain}
    Check User Groups    ${username}    ${domain}    ${remote_group}
    Close Focused Window


Log in with remote user with local password
    Open GNOME Terminal In Sudo Mode
    Log In With Remote User Through CLI: Local Password    ${username}    ${domain}    ${local_password}
    Check That Remote User Can Run Sudo Commands    ${local_password}
