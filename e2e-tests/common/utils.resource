*** Settings ***
Documentation       authd test resources

Resource            kvm.resource
Library             ${CURDIR}/StringUtils.py    AS    StringUtils
Library             Process


*** Variables ***
${IMAGES_DIR}    ${CURDIR}/images
${SCRIPTS_DIR}    ${CURDIR}/scripts


*** Keywords ***
Log In
    PlatformVideoInput.Match Text    Not listed    120
    PlatformHid.Keys Combo    Return
    BuiltIn.Sleep    2
    PlatformHid.Type String    ubuntu
    BuiltIn.Sleep    2
    PlatformHid.Keys Combo    Return
    BuiltIn.Sleep    2
    PlatformVideoInput.Match    ${IMAGES_DIR}/circle-of-friends.png    60


Log Out
    Run Command    gnome-session-quit --logout --no-prompt


Open GNOME Terminal
    Start Application    /usr/bin/gnome-terminal
    PlatformVideoInput.Match Text    @ubuntu:~$    15
    PlatformHid.Keys Combo    Super_L    Up


Open GNOME Terminal In Sudo Mode
    Open GNOME Terminal
    Enter Sudo Mode In GNOME Terminal


Enter Sudo Mode In GNOME Terminal
    PlatformHid.Type String    clear
    PlatformHid.Keys Combo    Return
    PlatformHid.Type String    sudo -s
    PlatformHid.Keys Combo    Return
    PlatformVideoInput.Match Text    [sudo] password for ubuntu
    PlatformHid.Type String    ubuntu
    PlatformHid.Keys Combo    Return
    PlatformVideoInput.Match Text    root@ubuntu    15
    PlatformHid.Type String    clear
    PlatformHid.Keys Combo    Return
    PlatformVideoInput.Match Text    root@ubuntu    15


Close Focused Window
    PlatformHid.Keys Combo    Alt_L   F4


Close GNOME Terminal In Sudo Mode
    PlatformHid.Type String    clear
    PlatformHid.Keys Combo    Return
    PlatformVideoInput.Match Text    root@ubuntu    15
    PlatformHid.Type String    exit
    PlatformHid.Keys Combo    Return
    Close Focused Window


Log Out From Terminal Session
    PlatformVideoInput.Match Text    @ubuntu    15
    PlatformHid.Type String    exit
    PlatformHid.Keys Combo    Return


# Hacky way of making the tool recognize that the command finished successfully by running it in the format of:
# $ clear && {command} && echo cmd-finished
Run Command In GNOME Terminal
    [Arguments]    ${command}
    ${ampersand}    Create List    Shift_L    7
    PlatformHid.Type String    clear
    PlatformHid.Keys Combo    space
    PlatformHid.Keys Combo    ${ampersand}
    PlatformHid.Keys Combo    ${ampersand}
    PlatformHid.Keys Combo    space
    PlatformHid.Type String    ${command}
    PlatformHid.Keys Combo    space
    PlatformHid.Keys Combo    ${ampersand}
    PlatformHid.Keys Combo    ${ampersand}
    PlatformHid.Keys Combo    space
    PlatformHid.Type String    clear
    PlatformHid.Keys Combo    space
    PlatformHid.Keys Combo    ${ampersand}
    PlatformHid.Keys Combo    ${ampersand}
    PlatformHid.Keys Combo    space
    PlatformHid.Type String    echo cmd-finished
    # Sleep a bit to ensure everything gets typed properly
    BuiltIn.Sleep    2    # hacky
    PlatformHid.Keys Combo    Return
    # Sleep a bit to avoid matching the text on the command itself
    BuiltIn.Sleep    2    # hacky
    PlatformVideoInput.Match Text    cmd-finished    600


Left Button Click
    BuiltIn.Sleep    0.5
    Click LEFT Button
    BuiltIn.Sleep    0.5
    Move Pointer To (100, 100)


Run Command
    [Arguments]    ${command}
    PlatformHid.Keys Combo    Alt_L    F2
    PlatformVideoInput.Match Text    Run a Command    15
    PlatformHid.Type String    ${command}
    PlatformHid.Keys Combo   Return


Start Application
    [Arguments]    ${application}
    Run Command    ${application}


Cancel Operation
    PlatformVideoInput.Match Text    @ubuntu    15
    PlatformHid.Keys Combo    Control_L    C


Update And Upgrade Packages
    Open GNOME Terminal In Sudo Mode
    Run Command In GNOME Terminal    apt-get update
    Run Command In GNOME Terminal    apt-get upgrade -y
    Close GNOME Terminal In Sudo Mode
