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
    !define VERSION "0.4.0"
!endif

; Repository root, passed by the Makefile (-DROOT=...). The fallback is for a
; hand-run from the repository directory.
!ifndef ROOT
    !define ROOT "."
!endif

!define APPNAME   "rossh"
!define DISPLAY   "rossh SSH server"
!define PUBLISHER "rossh"
!define PORT      2222     ; next to wSSH on 22; change once wSSH is gone

Name "${DISPLAY} ${VERSION}"
OutFile "${ROOT}/rossh-setup.exe"
InstallDir "$PROGRAMFILES\rossh"
InstallDirRegKey HKLM "Software\${APPNAME}" "InstallDir"

; Program Files and the service both need administrator rights.
RequestExecutionLevel admin
SetCompressor /SOLID lzma

!include "MUI2.nsh"
!include "LogicLib.nsh"

!define MUI_ABORTWARNING
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "${ROOT}/LICENSE"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"
!insertmacro MUI_LANGUAGE "German"

Section "rossh" SecInstall
    SetOutPath "$INSTDIR"
    File "${ROOT}/rossh.exe"
    File "${ROOT}/LICENSE"
    File "${ROOT}/README.md"

    ; The whole setup, in one call: host key, rossh.conf, an authorised key,
    ; the service (auto-start) and the firewall. With no --key it generates a
    ; client key next to the config, so there is always a way in.
    DetailPrint "Setting up rossh in $INSTDIR ..."
    nsExec::ExecToLog '"$INSTDIR\rossh.exe" setup --port ${PORT} "$INSTDIR"'
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

    nsExec::ExecToLog 'netsh advfirewall firewall delete rule name="rossh ${PORT}"'
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
    Delete "$INSTDIR\rossh.log"
    Delete "$INSTDIR\kh"
    Delete "$INSTDIR\known_hosts"
    RMDir "$INSTDIR"

    Delete "$SMPROGRAMS\${APPNAME}\*.lnk"
    RMDir "$SMPROGRAMS\${APPNAME}"

    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}"
    DeleteRegKey HKLM "Software\${APPNAME}"
SectionEnd
