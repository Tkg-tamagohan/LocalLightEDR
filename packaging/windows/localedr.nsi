; LocalEDR Windows x64 NSIS Installer
; Delegates transactional file replacement, DACLs, SCM service registration,
; Native Messaging machine setup, and rollback to 64-bit PowerShell scripts.

Unicode True

!ifndef VERSION
  !define VERSION "0.1.0"
!endif
!ifndef BIN_DIR
  !define BIN_DIR "..\..\target\release"
!endif
!ifndef RULES_DIR
  !define RULES_DIR "..\..\rules"
!endif
!ifndef OUT_FILE
  !define OUT_FILE "..\..\dist\LocalEDR-Setup-v${VERSION}-win-x64.exe"
!endif

!define APP_NAME "LocalEDR"
!define ARP_REG_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\LocalEDR"

Name "${APP_NAME} v${VERSION}"
OutFile "${OUT_FILE}"
InstallDir "$PROGRAMFILES64\${APP_NAME}"
RequestExecutionLevel admin
ManifestDPIAware true
SetCompressor /SOLID lzma

VIProductVersion "${VERSION}.0"
VIAddVersionKey "ProductName" "${APP_NAME}"
VIAddVersionKey "CompanyName" "${APP_NAME}"
VIAddVersionKey "FileDescription" "${APP_NAME} Installer"
VIAddVersionKey "FileVersion" "${VERSION}"
VIAddVersionKey "ProductVersion" "${VERSION}"
VIAddVersionKey "LegalCopyright" "MIT OR Apache-2.0"

!include "MUI2.nsh"
!include "x64.nsh"
!include "FileFunc.nsh"
!include "LogicLib.nsh"

Var UpdateModeFlag
Var PurgeDataFlag
Var PsExitCode

!define MUI_ABORTWARNING
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"
!insertmacro MUI_LANGUAGE "Japanese"

Function .onInit
  ${IfNot} ${RunningX64}
    MessageBox MB_ICONSTOP "${APP_NAME} requires 64-bit Windows (x64)."
    Abort
  ${EndIf}

  SetRegView 64
  StrCpy $UpdateModeFlag "0"

  ${GetParameters} $R0
  ClearErrors
  ${GetOptions} $R0 "/UPDATE" $R1
  ${IfNot} ${Errors}
    StrCpy $UpdateModeFlag "1"
    SetSilent silent
  ${EndIf}
FunctionEnd

Section "${APP_NAME}" SecMain
  InitPluginsDir
  SetOutPath "$PLUGINSDIR\payload"

  File "${BIN_DIR}\ledr-daemon.exe"
  File "${BIN_DIR}\ledr-ui.exe"
  File "${BIN_DIR}\ledr-bridge-nm.exe"
  File "${BIN_DIR}\ledr-auth-helper.exe"
  File "install.ps1"
  File "uninstall.ps1"

  SetOutPath "$PLUGINSDIR\payload\rules"
  File "${RULES_DIR}\lotl_core.json"
  File "${RULES_DIR}\default_allowlist.json"

  StrCpy $R2 ""
  ${If} $UpdateModeFlag == "1"
    StrCpy $R2 " -UpdateMode"
  ${EndIf}

  ${DisableX64FSRedirection}
  ExecWait '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$PLUGINSDIR\payload\install.ps1" -SourceDir "$PLUGINSDIR\payload" -InstallDir "$INSTDIR" -DataDir "C:\ProgramData\LocalEDR"$R2' $PsExitCode
  ${EnableX64FSRedirection}

  ${If} $PsExitCode != 0
    SetErrorLevel $PsExitCode
    Abort "${APP_NAME} installation failed (exit code $PsExitCode). Inspect C:\ProgramData\LocalEDR\logs\installer.log."
  ${EndIf}

  ClearErrors
  WriteUninstaller "$INSTDIR\uninstall.exe"
  ${If} ${Errors}
    SetErrorLevel 1
    Abort "Failed to write $INSTDIR\uninstall.exe."
  ${EndIf}

  SetRegView 64
  WriteRegStr HKLM "${ARP_REG_KEY}" "DisplayName" "${APP_NAME}"
  WriteRegStr HKLM "${ARP_REG_KEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "${ARP_REG_KEY}" "Publisher" "${APP_NAME}"
  WriteRegStr HKLM "${ARP_REG_KEY}" "DisplayIcon" "$INSTDIR\ledr-ui.exe"
  WriteRegStr HKLM "${ARP_REG_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "${ARP_REG_KEY}" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegStr HKLM "${ARP_REG_KEY}" "QuietUninstallString" '"$INSTDIR\uninstall.exe" /S'
  WriteRegDWORD HKLM "${ARP_REG_KEY}" "NoModify" 1
  WriteRegDWORD HKLM "${ARP_REG_KEY}" "NoRepair" 1
SectionEnd

Function un.onInit
  SetRegView 64
  StrCpy $PurgeDataFlag "0"

  ${GetParameters} $R0
  ClearErrors
  ${GetOptions} $R0 "/PURGE_DATA" $R1
  ${IfNot} ${Errors}
    StrCpy $PurgeDataFlag "1"
  ${EndIf}
FunctionEnd

Section "Uninstall"
  InitPluginsDir

  ${IfNot} ${FileExists} "$INSTDIR\uninstall.ps1"
    SetErrorLevel 1
    Abort "Missing $INSTDIR\uninstall.ps1; cannot safely run uninstall."
  ${EndIf}

  CopyFiles /SILENT "$INSTDIR\uninstall.ps1" "$PLUGINSDIR\uninstall.ps1"

  StrCpy $R2 ""
  ${If} $PurgeDataFlag == "1"
    StrCpy $R2 " -PurgeData"
  ${EndIf}

  ${DisableX64FSRedirection}
  ExecWait '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$PLUGINSDIR\uninstall.ps1" -InstallDir "$INSTDIR" -DataDir "C:\ProgramData\LocalEDR"$R2' $PsExitCode
  ${EnableX64FSRedirection}

  ${If} $PsExitCode != 0
    SetErrorLevel $PsExitCode
    Abort "${APP_NAME} uninstallation failed (exit code $PsExitCode)."
  ${EndIf}

  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"
  SetRegView 64
  DeleteRegKey HKLM "${ARP_REG_KEY}"
SectionEnd
