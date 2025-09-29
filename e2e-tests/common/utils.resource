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
    Match Text    Not listed    120
    Hid.Keys Combo    Return
    BuiltIn.Sleep    2
    Hid.Type String    ubuntu
    BuiltIn.Sleep    2
    Hid.Keys Combo    Return
    BuiltIn.Sleep    2
    Move Pointer To Proportional (0, 1)
    Match Text    Show Apps    15


Log Out
    Run Command    gnome-session-quit --logout --no-prompt


Open GNOME Terminal
    Hid.Keys Combo    Control_L    Alt_L    t
    Match Text    @ubuntu:~$    15
    Hid.Keys Combo    F11


Open GNOME Terminal In Sudo Mode
    Open GNOME Terminal
    Enter Sudo Mode In GNOME Terminal


Enter Sudo Mode In GNOME Terminal
    Hid.Type String    clear
    Hid.Keys Combo    Return
    Hid.Type String    sudo -s
    Hid.Keys Combo    Return
    Match Text    [sudo] password for ubuntu
    Hid.Type String    ubuntu
    Hid.Keys Combo    Return
    Match Text    root@ubuntu    15
    Hid.Type String    clear
    Hid.Keys Combo    Return
    Match Text    root@ubuntu    15


Close Focused Window
    Hid.Keys Combo    Alt_L   F4


Close GNOME Terminal In Sudo Mode
    Hid.Type String    clear
    Hid.Keys Combo    Return
    Match Text    root@ubuntu    15
    Hid.Type String    exit
    Hid.Keys Combo    Return
    Close Focused Window


Log Out From Terminal Session
    Match Text    @ubuntu    15
    Hid.Type String    exit
    Hid.Keys Combo    Return


# Hacky way of making the tool recognize that the command finished successfully by running it in the format of:
# $ clear && {command} && echo cmd-finished
# Run Command In GNOME Terminal
#     [Arguments]    ${command}
#     ${ampersand}    Create List    Shift_L    7
#     Hid.Type String    clear
#     Hid.Keys Combo    space
#     Hid.Keys Combo    ${ampersand}
#     Hid.Keys Combo    ${ampersand}
#     Hid.Keys Combo    space
#     Hid.Type String    ${command}
#     Hid.Keys Combo    space
#     Hid.Keys Combo    ${ampersand}
#     Hid.Keys Combo    ${ampersand}
#     Hid.Keys Combo    space
#     Hid.Type String    clear
#     Hid.Keys Combo    space
#     Hid.Keys Combo    ${ampersand}
#     Hid.Keys Combo    ${ampersand}
#     Hid.Keys Combo    space
#     Hid.Type String    echo cmd-finished
#     # Sleep a bit to ensure everything gets typed properly
#     BuiltIn.Sleep    2    # hacky
#     Hid.Keys Combo    Return
#     # Sleep a bit to avoid matching the text on the command itself
#     BuiltIn.Sleep    2    # hacky
#     Match Text    cmd-finished    600
Run Command In GNOME Terminal
    [Arguments]    ${command}
    Hid.Type String    ${command}
    Hid.Type String   clear && ${command} && clear && echo cmd-finished
    Hid.Keys Combo    Return
    BuiltIn.Sleep    2
    Match Text    cmd-finished    600

Left Button Click
    BuiltIn.Sleep    0.5
    Click LEFT Button
    BuiltIn.Sleep    0.5
    Move Pointer To Proportional (1, 1)


Run Command
    [Arguments]    ${command}
    Hid.Keys Combo    Alt_L    F2
    Match Text    Run a Command    15
    Hid.Type String    ${command}
    Hid.Keys Combo   Return


Start Application
    [Arguments]    ${application}
    Run Command    ${application}


Cancel Operation
    Match Text    @ubuntu    15
    Hid.Keys Combo    Control_L    C


Update And Upgrade Packages
    Open GNOME Terminal In Sudo Mode
    Run Command In GNOME Terminal    apt-get update
    Run Command In GNOME Terminal    apt-get upgrade -y
    Close GNOME Terminal In Sudo Mode
