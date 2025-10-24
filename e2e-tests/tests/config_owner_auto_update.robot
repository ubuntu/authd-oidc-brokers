*** Settings ***
Resource        ./resources/authd/utils.resource
Resource        ./resources/authd/authd.resource

Resource        ./resources/broker/broker.resource

Test Tags       robot:exit-on-failure

Test Teardown    Log Videos On Error

*** Variables ***
${username}    %{E2E_USER}
${local_password}    qwer1234


*** Test Cases ***
Log in with local user
    Log In


Try to log in with remote user
    Open Terminal
    Log In With Remote User Through CLI: QR Code    ${username}    ${local_password}
    Log Out From Terminal Session
    Close Focused Window


Check that owner was updated in broker configuration
    Open Terminal In Sudo Mode
    Check Configuration Value    owner    %{username}
