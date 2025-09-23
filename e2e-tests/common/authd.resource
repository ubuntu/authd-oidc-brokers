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
    Hid.Type String    add-apt-repository ppa:ubuntu-enterprise-desktop/authd-edge -y
    Hid.Keys Combo    Return
    Match Text    Reading package lists... Done    60
    Close GNOME Terminal In Sudo Mode


Disable Authd Socket and Service
    Open GNOME Terminal In Sudo Mode
    Run Command In GNOME Terminal    systemctl disable --now authd.socket
    Run Command In GNOME Terminal    systemctl disable --now authd.service
    Close GNOME Terminal In Sudo Mode


Get NSS Passwd Entry For Remote User
    [Arguments]    ${username}
    Hid.Type String    getent passwd ${username}
    Hid.Keys Combo    Return


Get NSS Group Entries For Remote User
    [Arguments]    ${username}
    Hid.Type String    groups ${username}
    Hid.Keys Combo    Return


Change Local Password Of Remote User
    [Arguments]    ${username}    ${local_password}    ${new_password}
    Hid.Type String    passwd ${username}
    Hid.Keys Combo    Return

    Match Text    Enter your local password:    15
    Builtin.Sleep    2
    Hid.Type String    ${local_password}
    Hid.Keys Combo    Return

    Match Text    New password:    15
    Builtin.Sleep    2
    Hid.Type String    ${new_password}
    Hid.Keys Combo    Return

    Match Text    Confirm password:    15
    Builtin.Sleep    2
    Hid.Type String    ${new_password}
    Hid.Keys Combo    Return

    Match Text    passwd: password updated successfully    15


Try Log In With Remote User
    [Arguments]    ${username}
    Hid.Type String    login ${username}
    Hid.Keys Combo    Return


# Conditional checks
Check That Remote User Has No Available Authentication Modes
    Match Text    could not get authentication modes: no authentication modes available for user    30


Check That Log In Fails Because Authd Is Disabled
    Match Text    could not connect to unix:///run/authd.sock    30


Check That User Is Redirected To Local Broker
    Match Text    Password:    30


Check That User Information Can Not Be Fetched
    Match Text    authentication failure: could not fetch user info    30


Check That Remote User Can Run Sudo Commands
    [Arguments]    ${local_password}
    Hid.Type String    sudo touch sudo-test.txt
    Hid.Keys Combo    Return
    Builtin.Sleep    2
    Match Text    Enter your local password:    15
    Builtin.Sleep    2
    Hid.Type String    ${local_password}
    Hid.Keys Combo    Return
    Builtin.Sleep    2
    Hid.Type String    ls -l
    Hid.Keys Combo    Return
    Match Text    sudo-test.txt    15
