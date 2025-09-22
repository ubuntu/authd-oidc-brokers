*** Settings ***
Documentation       MS Entra ID specific resources for the tests

Resource            kvm.resource
Resource            ${AUTHD_COMMON}/utils.resource

Library            Process

*** Variables ***
${AUTHD_COMMON}    ${CURDIR}/../authd-common
${ENTRAID_COMMON}    ${CURDIR}/../broker-common

${AUTHD_BROKER_CFG}    /etc/authd/brokers.d/msentraid.conf
${ENTRAID_BROKER_CFG}    /var/snap/authd-msentraid/current/broker.conf
${ENTRAID_BROKER_CFG_DIR}    /var/snap/authd-msentraid/current/broker.conf.d


*** Keywords ***
Enable Edge Broker
    Open GNOME Terminal In Sudo Mode
    Run Command In GNOME Terminal    snap refresh authd-msentraid --edge
    Close GNOME Terminal In Sudo Mode


Disable Broker And Purge Config
    Open GNOME Terminal In Sudo Mode
    Run Command In GNOME Terminal    snap stop authd-msentraid
    Run Command In GNOME Terminal    rm ${AUTHD_BROKER_CFG}
    Run Command In GNOME Terminal    systemctl restart authd.service
    Close GNOME Terminal In Sudo Mode


Log In With Remote User Through CLI: QR Code
    [Arguments]    ${username}    ${domain}    ${local_password}
    Open GNOME Terminal
    Start Log In With Remote User Through CLI: QR Code    ${username}    ${domain}
    Select Provider
    Continue Log In With Remote User: Log In On Browser    ${username}    ${domain}
    Continue Log In With Remote User Through CLI: Define Local Password    ${username}    ${domain}    ${local_password}


Start Log In With Remote User Through CLI: QR Code
    [Arguments]    ${username}    ${domain}
    # TODO: Workaround for the issue that `PlatformHid.Type String` doesnt
    #       correctly enter special characters which require a Shift modifier
    PlatformHid.Type String    sudo login ${username}
    PlatformHid.Keys Combo    Shift_L    @
    PlatformHid.Type String    ${domain}
    PlatformHid.Keys Combo    Return

    # Wait for the password prompt
    PlatformVideoInput.Match Text    [sudo] password for ubuntu

    # Enter the sudo password
    PlatformHid.Type String    ubuntu
    PlatformHid.Keys Combo    Return

    # Check that the provider selection contains the Entra ID provider
    PlatformVideoInput.Match Text    Select your provider    15


Select Provider
    # Check that the provider selection contains the Entra ID provider
    PlatformVideoInput.Match Text    Select your provider    15
    PlatformVideoInput.Match Text    2. Microsoft Entra ID

    # Select the Entra ID provider
    PlatformHid.Type String    2
    Builtin.Sleep    2

Regenerate QR Code
    # As long as we are in the login process, we can regenerate the QR code
    PlatformVideoInput.Match Text    Request new login code    30
    PlatformHid.Keys Combo    Return
    PlatformVideoInput.Match Text    https://microsoft.com/devicelogin    15


Continue Log In With Remote User: Log In On Browser
    [Arguments]    ${username}    ${domain}
    # Wait until the verification URL and login code are displayed
    PlatformVideoInput.Match Text    https://microsoft.com/devicelogin
    # Read the user code.
    ${text} =    PlatformVideoInput.Read Text
    ${user_code} =    StringUtils.FirstMatch    (https://)?microsoft.com/devicelogin\n((Login code: )?([A-Z0-9]+))    ${text}

    Start Process    ${ENTRAID_COMMON}/BrowserWindow.py    ${username}@${domain}    %{E2E_PASSWORD}    ${user_code}    alias=RemoteAuth
    Wait For Process    RemoteAuth
    Builtin.Sleep    5


Continue Log In With Remote User Through CLI: Define Local Password
    [Arguments]    ${username}    ${domain}    ${local_password}
    # The terminal should now be visible and focused again.
    # Check that we're prompted to set a local password.
    PlatformVideoInput.Match Text    New password:

    # Set a local password
    PlatformHid.Type String    ${local_password}
    PlatformHid.Keys Combo    Return

    # Confirm the local password
    PlatformVideoInput.Match Text    Confirm password:
    PlatformHid.Type String    ${local_password}
    PlatformHid.Keys Combo    Return

    # Wait for the login to complete
    ${timeout_sec} =    Set Variable    30
    PlatformVideoInput.Match Text    ${username}@${domain}@ubuntu    ${timeout_sec}


Log In With Remote User Through CLI: Local Password
    [Arguments]    ${username}    ${domain}    ${local_password}
    PlatformHid.Type String    login ${username}
    # TODO: Workaround for the issue that `PlatformHid.Type String` doesnt
    #       correctly enter special characters which require a Shift modifier
    PlatformHid.Keys Combo    Shift_L    @
    PlatformHid.Type String    ${domain}
    PlatformHid.Keys Combo    Return
    Builtin.Sleep    2
    PlatformVideoInput.Match Text    Enter your local password:    30
    PlatformHid.Type String    ${local_password}
    PlatformHid.Keys Combo    Return
    Builtin.Sleep    2
    PlatformVideoInput.Match Text    ${username}@${domain}@ubuntu:~$    30


# Uses sed to change the broker configuration.
# It should match both commented and uncommented lines.
# The full commands looks like:
#     sed -i 's/#*${config_key} = .*/${config_key} = ${config_value}/g' ${ENTRAID_BROKER_CFG}
Change Broker Configuration
    [arguments]    ${config_key}    ${config_value}
    Open GNOME Terminal In Sudo Mode
    PlatformHid.Type String    sed -i 's/
    # TODO: Workaround for the issue that `PlatformHid.Type String` doesnt
    #       correctly enter special characters which require a Shift modifier
    PlatformHid.Keys Combo    Shift_L     \#
    # TODO: Workaround for the issue that `PlatformHid.Type String` doesnt
    #       correctly enter special characters which require a Shift modifier
    PlatformHid.Keys Combo    Shift_L     *
    PlatformHid.Type String    ${config_key} =.
    # TODO: Workaround for the issue that `PlatformHid.Type String` doesnt
    #       correctly enter special characters which require a Shift modifier
    PlatformHid.Keys Combo    Shift_L     *
    PlatformHid.Type String   /${config_key} = ${config_value}/g' ${ENTRAID_BROKER_CFG}
    PlatformHid.Keys Combo    Return
    Run Command In GNOME Terminal    snap restart authd-msentraid
    Close GNOME Terminal In Sudo Mode


# Pretty much the same as the function above, but since YARF does not have support for
# shifted characters yet, we need to do some workarounds.
Change allowed_users In Broker Configuration
    [arguments]    ${config_value}
    Open GNOME Terminal In Sudo Mode
    PlatformHid.Type String    sed -i 's/
    # TODO: Workaround for the issue that `PlatformHid.Type String` doesnt
    #       correctly enter special characters which require a Shift modifier
    PlatformHid.Keys Combo    Shift_L     \#
    # TODO: Workaround for the issue that `PlatformHid.Type String` doesnt
    #       correctly enter special characters which require a Shift modifier
    PlatformHid.Keys Combo    Shift_L     *
    PlatformHid.Type String    allowed
    # TODO: Workaround for the issue that `PlatformHid.Type String` doesnt
    #       correctly enter special characters which require a Shift modifier
    PlatformHid.Keys Combo    Shift_L     _
    PlatformHid.Type String    users = .
    # TODO: Workaround for the issue that `PlatformHid.Type String` doesnt
    #       correctly enter special characters which require a Shift modifier
    PlatformHid.Keys Combo    Shift_L     *
    PlatformHid.Type String   /
    PlatformHid.Type String    allowed
    # TODO: Workaround for the issue that `PlatformHid.Type String` doesnt
    #       correctly enter special characters which require a Shift modifier
    PlatformHid.Keys Combo    Shift_L     _
    PlatformHid.Type String    users = ${config_value}/g' ${ENTRAID_BROKER_CFG}
    PlatformHid.Keys Combo    Return
    Run Command In GNOME Terminal    snap restart authd-msentraid
    Close GNOME Terminal In Sudo Mode


Comment Key In Broker Configuration
    [arguments]    ${config_key}
    Open GNOME Terminal In Sudo Mode
    PlatformHid.Type String    sed -i 's/
    # TODO: Workaround for the issue that `PlatformHid.Type String` doesnt
    #       correctly enter special characters which require a Shift modifier
    PlatformHid.Keys Combo    Shift_L     \#
    # TODO: Workaround for the issue that `PlatformHid.Type String` doesnt
    #       correctly enter special characters which require a Shift modifier
    PlatformHid.Keys Combo    Shift_L     *
    PlatformHid.Type String    ${config_key} =.
    # TODO: Workaround for the issue that `PlatformHid.Type String` doesnt
    #       correctly enter special characters which require a Shift modifier
    PlatformHid.Keys Combo    Shift_L     *
    PlatformHid.Type String   /
    # TODO: Workaround for the issue that `PlatformHid.Type String` doesnt
    #       correctly enter special characters which require a Shift modifier
    PlatformHid.Keys Combo    Shift_L     \#
    PlatformHid.Type String    ${config_key} =/g' ${ENTRAID_BROKER_CFG}
    PlatformHid.Keys Combo    Return
    Run Command In GNOME Terminal    snap restart authd-msentraid
    Close GNOME Terminal In Sudo Mode


Log In With Remote User Through SSH: QR Code
    [Arguments]    ${username}    ${domain}    ${local_password}
    Start Log In With Remote User Through SSH: QR Code    ${username}    ${domain}
    Select Provider through SSH
    Continue Log In With Remote User: Log In On Browser    ${username}    ${domain}
    Continue Log In With Remote User Through SSH: QR Code
    Continue Log In With Remote User Through SSH: Define Local Password    ${local_password}


Start Log In With Remote User Through SSH: QR Code
    [Arguments]    ${username}    ${domain}
    PlatformHid.Type String    ssh ${username}
    # TODO: Workaround for the issue that `PlatformHid.Type String` doesnt
    #       correctly enter special characters which require a Shift modifier
    PlatformHid.Keys Combo    Shift_L    @
    PlatformHid.Type String    ${domain}
    # TODO: Workaround for the issue that `PlatformHid.Type String` doesnt
    #       correctly enter special characters which require a Shift modifier
    PlatformHid.Keys Combo    Shift_L    @
    PlatformHid.Type String    localhost
    PlatformHid.Keys Combo    Return
    Builtin.Sleep    2

    PlatformHid.Type String    yes
    PlatformHid.Keys Combo    Return


Select Provider through SSH
    PlatformVideoInput.Match Text    2. Microsoft Entra ID    30
    PlatformVideoInput.Match Text    Choose your provider:    30
    PlatformHid.Type String    2
    PlatformHid.Keys Combo    Return


Continue Log In With Remote User Through SSH: QR Code
    PlatformVideoInput.Match Text    Choose action:    30
    PlatformHid.Type String    1
    PlatformHid.Keys Combo    Return


Continue Log In With Remote User Through SSH: Define Local Password
    [Arguments]    ${local_password}
    PlatformVideoInput.Match Text    Create a local password:    30
    PlatformHid.Type String    ${local_password}
    PlatformHid.Keys Combo    Return

    PlatformVideoInput.Match Text    Confirm Password:    30
    PlatformHid.Type String    ${local_password}
    PlatformHid.Keys Combo    Return

    PlatformVideoInput.Match Text    ${username}@${domain}@ubuntu:~$    30


Log In With Remote User Through SSH: Local Password
    [Arguments]    ${username}    ${domain}    ${local_password}
    PlatformHid.Type String    ssh ${username}
    # TODO: Workaround for the issue that `PlatformHid.Type String` doesnt
    #       correctly enter special characters which require a Shift modifier
    PlatformHid.Keys Combo    Shift_L    @
    PlatformHid.Type String    ${domain}
    # TODO: Workaround for the issue that `PlatformHid.Type String` doesnt
    #       correctly enter special characters which require a Shift modifier
    PlatformHid.Keys Combo    Shift_L    @
    PlatformHid.Type String    localhost
    PlatformHid.Keys Combo    Return

    PlatformVideoInput.Match Text    Enter your local password:    30
    PlatformHid.Type String    ${local_password}
    PlatformHid.Keys Combo    Return

    PlatformVideoInput.Match Text    ${username}@${domain}@ubuntu:~$    30


Log In With Remote User Through GDM: QR Code
    [Arguments]    ${username}    ${domain}    ${local_password}
    Start Log In With Remote User Through GDM: QR Code    ${username}    ${domain}
    Select Broker Through GDM
    Continue Log In With Remote User: Log In On Browser    ${username}    ${domain}
    Continue Log In With Remote User Through GDM: Define Local Password    ${local_password}



Start Log In With Remote User Through GDM: QR Code
    [Arguments]    ${username}    ${domain}
    PlatformVideoInput.Match Text    Not listed    180
    Move Pointer To Not Listed
    Left Button Click

     # Enter the username
    PlatformVideoInput.Match Text    Username
    # TODO: Workaround for the issue that `PlatformHid.Type String` doesnt
    #       correctly enter special characters which require a Shift modifier
    PlatformHid.Type String    ${username}
    PlatformHid.Keys Combo    Shift_L    @
    PlatformHid.Type String    ${domain}
    PlatformHid.Keys Combo    Return


Select Broker Through GDM
    PlatformVideoInput.Match Text    Select the broker    30
    Move Pointer To Microsoft Entra ID
    Left Button Click
    Builtin.Sleep    1


Continue Log In With Remote User Through GDM: Define Local Password
    [Arguments]    ${local_password}
    PlatformVideoInput.Match Text    Create a local password    30
    PlatformHid.Type String    ${local_password}
    PlatformHid.Keys Combo    Return

    PlatformVideoInput.Match Text   Please, type the new passphrase again    30
    PlatformHid.Type String    ${local_password}
    PlatformHid.Keys Combo    Return

    PlatformVideoInput.Match Text    Welcome to Ubuntu    30


Log In With Remote User Through GDM: Local Password
    [Arguments]    ${username}    ${domain}    ${local_password}
    PlatformVideoInput.Match Text    Not listed    180
    Move Pointer To Not Listed
    Left Button Click

    # Enter the username
    PlatformVideoInput.Match Text    Username
    # TODO: Workaround for the issue that `PlatformHid.Type String` doesnt
    #       correctly enter special characters which require a Shift modifier
    PlatformHid.Type String    ${username}
    PlatformHid.Keys Combo    Shift_L    @
    PlatformHid.Type String    ${domain}
    PlatformHid.Keys Combo    Return

    # Enter the password
    PlatformVideoInput.Match Text    Password
    PlatformHid.Type String   ${local_password}
    PlatformHid.Keys Combo    Return

    # Wait for GNOME initial setup
    PlatformVideoInput.Match Text    Welcome to Ubuntu    600


Check User Information
    [Arguments]    ${username}    ${domain}
    PlatformVideoInput.Match Text    ${username}@${domain}:x:    30


Check User Groups
    [Arguments]    ${username}    ${domain}    ${remote_group}
    PlatformVideoInput.Match Text    ${username}@${domain} sudo ${remote_group}    30


Check Configuration Value
    [Arguments]    ${config_key}    ${expected_value}
    PlatformHid.Type String    cat ${ENTRAID_BROKER_CFG}
    # TODO: Workaround for the issue that `PlatformHid.Type String` doesnt
    #       correctly enter special characters which require a Shift modifier
    PlatformHid.Keys Combo    Shift_L    |
    PlatformHid.Type String    grep ${config_key}
    PlatformHid.Keys Combo    Return
    PlatformVideoInput.Match Text    ${expected_value}    30


Check If Owner Was Registered
    [Arguments]    ${username}
    PlatformHid.Type String    cat ${ENTRAID_BROKER_CFG_DIR}/20-owner-autoregistration.conf
    PlatformHid.Keys Combo    Return
    PlatformVideoInput.Match Text    owner = ${username}    30


Check Home Directory
    [Arguments]    ${username}    ${domain}
    PlatformHid.Type String    echo
    PlatformHid.Keys Combo    Shift_L    $
    PlatformHid.Type String    HOME
    PlatformHid.Keys Combo    Return
    PlatformVideoInput.Match Text    /home/${username}@${domain}    30

    PlatformHid.Type String    ls -l
    PlatformHid.Keys Combo    Return
    PlatformVideoInput.Match Text    ${username}@${domain} ${username}@${domain}


Check That Remote User Is Not Allowed To Log In
    PlatformVideoInput.Match Text    authentication failure: user not allowed in broker configuration    60
