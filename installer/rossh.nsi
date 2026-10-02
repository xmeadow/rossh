; rossh installer — a thin wrapper around `rossh setup` (spec.md §10, M4d).
;
; The binary already knows how to set a machine up (host key, config, an
; authorised key, the service, the firewall). This script only packages it:
; copy the files, call `rossh setup`, and register an uninstaller that calls
; `rossh --uninstall`. Everything below is plumbing, not logic.
;
; Build with:  make installer     (runs makensis; see the Makefile)
; Silent test: rossh-setup.exe /S /D=C:\rossh

!ifndef VERSION
    !define VERSION "0.5.0"
!endif

; Repository root, passed by the Makefile (-DROOT=...). The fallback is for a
; hand-run from the repository directory.
!ifndef ROOT
    !define ROOT "."
!endif

!define APPNAME   "rossh"
!define DISPLAY   "rossh SSH server"
!define PUBLISHER "xmeadow"
!define PORT      22       ; the stock SSH is gone; 22 is free. The install page
                          ; overrides this.

Name "${DISPLAY} ${VERSION}"
OutFile "${ROOT}/rossh-setup.exe"
InstallDir "$PROGRAMFILES\rossh"
InstallDirRegKey HKLM "Software\${APPNAME}" "InstallDir"

; Program Files and the service both need administrator rights.
RequestExecutionLevel admin
SetCompressor /SOLID lzma

!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "nsDialogs.nsh"

Var PortEdit
Var PortText
Var KeyEdit
Var KeyText

!define MUI_ABORTWARNING
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "${ROOT}/LICENSE"
!insertmacro MUI_PAGE_DIRECTORY
Page custom KeyPageCreate KeyPageLeave
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"
!insertmacro MUI_LANGUAGE "German"

; Ask for the public key the operator will connect with. Without it, setup
; generates a client key that lives on this machine — fine for a test, useless
; for reaching the box from elsewhere. Skipped entirely in a silent install
; (/S), which falls back to the generated key.
Function KeyPageCreate
    !insertmacro MUI_HEADER_TEXT "Server settings" "Listening port, and the key you will connect with."
    nsDialogs::Create 1018
    Pop $0
    ${If} $0 == error
        Abort
    ${EndIf}
    ${If} $PortText == ""
        StrCpy $PortText "${PORT}"
    ${EndIf}
    ${NSD_CreateLabel} 0 0 100% 10u "Listening port (22 replaces a stock SSH server):"
    Pop $0
    ${NSD_CreateText} 0 12u 30% 12u "$PortText"
    Pop $PortEdit
    ${NSD_CreateLabel} 0 36u 100% 24u "Authorized key file (one or more ssh-ed25519 lines), e.g. C:\rossh-key.pub.$\r$\nLeave it empty to have rossh generate a client key next to the config instead."
    Pop $0
    ${NSD_CreateText} 0 62u 78% 12u "$KeyText"
    Pop $KeyEdit
    ${NSD_CreateBrowseButton} 80% 62u 20% 12u "Browse..."
    Pop $4
    ${NSD_OnClick} $4 KeyBrowse
    nsDialogs::Show
FunctionEnd

Function KeyBrowse
    nsDialogs::SelectFileDialog open "$KeyText" "Public keys (*.pub)|*.pub|All files (*.*)|*.*"
    Pop $0
    ${If} $0 != ""
        ${NSD_SetText} $KeyEdit "$0"
    ${EndIf}
FunctionEnd

Function KeyPageLeave
    ${NSD_GetText} $PortEdit $PortText
    ${NSD_GetText} $KeyEdit $KeyText
    ; A blank port falls back to the build-time default; anything else must be a
    ; real port. Compare through LogicLib: hand-written jump labels are easy to
    ; get wrong (a duplicated label makes the installer loop forever).
    ${If} $PortText != ""
        ${If} $PortText < 1
        ${OrIf} $PortText > 65535
            MessageBox MB_ICONEXCLAMATION "Port must be between 1 and 65535."
            Abort
        ${EndIf}
    ${EndIf}
FunctionEnd

Section "rossh" SecInstall
    SetOutPath "$INSTDIR"
    File "${ROOT}/rossh.exe"
    File "${ROOT}/LICENSE"
    File "${ROOT}/README.md"

    ; wolfSSL and wolfSSH are linked statically, so their code is inside
    ; rossh.exe and their copyright notices travel with it. GPLv3 section 4
    ; wants those notices kept intact, and a binary-only install is where they
    ; would otherwise be lost. Renamed to .txt because ReactOS and older
    ; Windows have no association for an extensionless file, so Notepad opens
    ; these on a double click.
    SetOutPath "$INSTDIR\licenses"
    File "/oname=wolfssl-COPYING.txt"   "${ROOT}/third_party/wolfssl/COPYING"
    File "/oname=wolfssl-LICENSING.txt" "${ROOT}/third_party/wolfssl/LICENSING"
    File "/oname=wolfssh-LICENSING.txt" "${ROOT}/third_party/wolfssh/LICENSING"
    SetOutPath "$INSTDIR"

    ; The whole setup, in one call: host key, rossh.conf, the authorised key
    ; (the file named on the page, or one generated here), the service
    ; (auto-start) and the firewall.
    StrCpy $1 "${PORT}"
    ${If} $PortText != ""
        StrCpy $1 "$PortText"
    ${EndIf}
    WriteRegStr HKLM "Software\${APPNAME}" "Port" "$1"

    DetailPrint "Setting up rossh in $INSTDIR on port $1 ..."
    ${If} $KeyText != ""
        nsExec::ExecToLog '"$INSTDIR\rossh.exe" setup --port $1 --key "$KeyText" "$INSTDIR"'
    ${Else}
        nsExec::ExecToLog '"$INSTDIR\rossh.exe" setup --port $1 "$INSTDIR"'
    ${EndIf}
    Pop $0
    ${If} $0 != 0
        ; Anything but 0 means the service could not be installed — usually
        ; because the installer was not elevated. Say so; do not half-install.
        MessageBox MB_ICONSTOP "rossh setup failed (exit $0).$\r$\nThe service was not installed."
        SetErrorLevel 1
        Abort
    ${EndIf}

    ; Start menu
    CreateDirectory "$SMPROGRAMS\${APPNAME}"
    CreateShortCut "$SMPROGRAMS\${APPNAME}\rossh (console).lnk" "$INSTDIR\rossh.exe"
    CreateShortCut "$SMPROGRAMS\${APPNAME}\Uninstall rossh.lnk" "$INSTDIR\uninst.exe"

    ; Add/Remove Programs
    WriteUninstaller "$INSTDIR\uninst.exe"
    WriteRegStr HKLM "Software\${APPNAME}" "InstallDir" "$INSTDIR"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "DisplayName"     "${DISPLAY}"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "DisplayVersion"  "${VERSION}"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "Publisher"       "${PUBLISHER}"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "UninstallString" '"$INSTDIR\uninst.exe"'
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "NoModify" 1
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "NoRepair" 1
SectionEnd

Section "Uninstall"
    ; Stop and remove the service first, while the binary is still there.
    nsExec::ExecToLog '"$INSTDIR\rossh.exe" --uninstall'
    Pop $0

    ; The firewall rule is named after the port we actually used, which the
    ; installer recorded in the registry (default to the build-time one).
    ReadRegStr $2 HKLM "Software\${APPNAME}" "Port"
    ${If} $2 == ""
        StrCpy $2 "${PORT}"
    ${EndIf}

    nsExec::ExecToLog 'netsh advfirewall firewall delete rule name="rossh $2"'
    Pop $0

    Delete "$INSTDIR\rossh.exe"
    Delete "$INSTDIR\LICENSE"
    Delete "$INSTDIR\README.md"
    Delete "$INSTDIR\uninst.exe"
    ; The generated identity, config, keys and log go too — an uninstall leaves
    ; no server behind.
    Delete "$INSTDIR\hostkey.der"
    Delete "$INSTDIR\hostkey.der.pub"
    Delete "$INSTDIR\rossh.conf"
    Delete "$INSTDIR\authorized_keys"
    Delete "$INSTDIR\client.der"
    Delete "$INSTDIR\client.der.pub"
    Delete "$INSTDIR\mykey.pub"
    Delete "$INSTDIR\rossh.log"
    Delete "$INSTDIR\kh"
    Delete "$INSTDIR\known_hosts"
    Delete "$INSTDIR\licenses\wolfssl-COPYING.txt"
    Delete "$INSTDIR\licenses\wolfssl-LICENSING.txt"
    Delete "$INSTDIR\licenses\wolfssh-LICENSING.txt"
    RMDir "$INSTDIR\licenses"
    RMDir "$INSTDIR"

    Delete "$SMPROGRAMS\${APPNAME}\*.lnk"
    RMDir "$SMPROGRAMS\${APPNAME}"

    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}"
    DeleteRegKey HKLM "Software\${APPNAME}"
SectionEnd
