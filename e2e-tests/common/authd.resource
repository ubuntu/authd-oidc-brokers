*** Settings ***
Documentation       Authd related test resources

Resource            kvm.resource
Resource            ${AUTHD_COMMON}/utils.resource


*** Variables ***
${AUTHD_COMMON}    ${CURDIR}/../authd-common
${IMAGES_DIR}    ${CURDIR}/images
${local_password}    qwer1234


*** Keywords ***
Enable Edge Repository for Authd
    Open GNOME Terminal In Sudo Mode
    PlatformHid.Type String    add-apt-repository ppa
    # TODO: Workaround for the issue that `PlatformHid.Type String` doesnt
    #       correctly enter special characters which require a Shift modifier
    PlatformHid.Keys Combo    Shift_L    :
    PlatformHid.Type String    ubuntu-enterprise-desktop/authd-edge -y
    PlatformHid.Keys Combo    Return
    PlatformVideoInput.Match Text    Reading package lists... Done    60
    Close GNOME Terminal In Sudo Mode


Disable Authd Socket and Service
    Open GNOME Terminal In Sudo Mode
    Run Command In GNOME Terminal    systemctl disable --now authd.socket
    Run Command In GNOME Terminal    systemctl disable --now authd.service
    Close GNOME Terminal In Sudo Mode


Get NSS Passwd Entry For Remote User
    [Arguments]    ${username}    ${domain}
    PlatformHid.Type String    getent passwd ${username}
    # TODO: Workaround for the issue that `PlatformHid.Type String` doesnt
    #       correctly enter special characters which require a Shift modifier
    PlatformHid.Keys Combo    Shift_L    @
    PlatformHid.Type String   ${domain}
    PlatformHid.Keys Combo    Return


Get NSS Group Entries For Remote User
    [Arguments]    ${username}    ${domain}
    PlatformHid.Type String    groups ${username}
    # TODO: Workaround for the issue that `PlatformHid.Type String` doesnt
    #       correctly enter special characters which require a Shift modifier
    PlatformHid.Keys Combo    Shift_L    @
    PlatformHid.Type String   ${domain}
    PlatformHid.Keys Combo    Return


Change Local Password Of Remote User
    [Arguments]    ${username}    ${domain}    ${local_password}    ${new_password}
    PlatformHid.Type String    passwd ${username}
    # TODO: Workaround for the issue that `PlatformHid.Type String` doesnt
    #       correctly enter special characters which require a Shift modifier
    PlatformHid.Keys Combo    Shift_L    @
    PlatformHid.Type String   ${domain}
    PlatformHid.Keys Combo    Return

    PlatformVideoInput.Match Text    Enter your local password:    15
    Builtin.Sleep    2
    PlatformHid.Type String    ${local_password}
    PlatformHid.Keys Combo    Return

    PlatformVideoInput.Match Text    New password:    15
    Builtin.Sleep    2
    PlatformHid.Type String    ${new_password}
    PlatformHid.Keys Combo    Return

    PlatformVideoInput.Match Text    Confirm password:    15
    Builtin.Sleep    2
    PlatformHid.Type String    ${new_password}
    PlatformHid.Keys Combo    Return

    PlatformVideoInput.Match Text    passwd: password updated successfully    15


Try Log In With Remote User
    [Arguments]    ${username}    ${domain}
    # TODO: Workaround for the issue that `PlatformHid.Type String` doesnt
    #       correctly enter special characters which require a Shift modifier
    PlatformHid.Type String    login ${username}
    PlatformHid.Keys Combo    Shift_L    @
    PlatformHid.Type String    ${domain}
    PlatformHid.Keys Combo    Return


# Conditional checks
Check That Remote User Has No Available Authentication Modes
    PlatformVideoInput.Match Text    could not get authentication modes: no authentication modes available for user    30


Check That Log In Fails Because Authd Is Disabled
    PlatformVideoInput.Match Text    could not connect to unix:///run/authd.sock    30


Check That User Is Redirected To Local Broker
    PlatformVideoInput.Match Text    Password:    30


Check That User Information Can Not Be Fetched
    PlatformVideoInput.Match Text    authentication failure: could not fetch user info    30


Check That Remote User Can Run Sudo Commands
    [Arguments]    ${local_password}
    PlatformHid.Type String    sudo touch sudo-test.txt
    PlatformHid.Keys Combo    Return
    Builtin.Sleep    2
    PlatformVideoInput.Match Text    Enter your local password:    15
    Builtin.Sleep    2
    PlatformHid.Type String    ${local_password}
    PlatformHid.Keys Combo    Return
    Builtin.Sleep    2
    PlatformHid.Type String    ls -l
    PlatformHid.Keys Combo    Return
    PlatformVideoInput.Match Text    sudo-test.txt    15
