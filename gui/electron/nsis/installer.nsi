# Custom NSIS script for KCP Proxy Client (electron-builder nsis.script).
#
# Base: app-builder-lib@26.15.3 templates/nsis/installer.nsi, copied verbatim
# except for the changes marked "DETAILS PATCH" below. If electron-builder is
# upgraded, re-diff this file against the new template and re-apply them.
#
# DETAILS PATCH 1: include our patched install section that shows real
# installation details (files, folders, shortcuts) instead of a bare bar.
# DETAILS PATCH 2: bilingual DetailPrint milestones (defined after addLangs so
# the language files are already loaded).

Var newStartMenuLink
Var oldStartMenuLink
Var newDesktopLink
Var oldDesktopLink
Var oldShortcutName
Var oldMenuDirectory

!include "common.nsh"
!include "MUI2.nsh"
!include "multiUser.nsh"
!include "allowOnlyOneInstallerInstance.nsh"

!ifdef BUILD_UNINSTALLER
  !ifmacrodef customUnInstallSection
    !define MUI_COMPONENTSPAGE_NODESC
    !insertmacro MUI_UNPAGE_COMPONENTS
  !endif
!endif

!ifdef INSTALL_MODE_PER_ALL_USERS
  !ifdef BUILD_UNINSTALLER
    RequestExecutionLevel user
  !else
    RequestExecutionLevel admin
  !endif
!else
  RequestExecutionLevel user
!endif

!ifdef BUILD_UNINSTALLER
  SilentInstall silent
!else
  Var appExe
  Var launchLink
!endif

!ifdef ONE_CLICK
  !include "oneClick.nsh"
!else
  !include "assistedInstaller.nsh"
!endif

# DETAILS PATCH 5b: custom-script mode never runs electron-builder's
# standalone uninstaller build, so assistedInstaller.nsh's BUILD_UNINSTALLER
# branch (which defines the uninstaller pages) does not compile. Define the
# uninstaller pages here instead, so the uninstaller embedded by
# WriteUninstaller (see installSection_details.nsh) keeps its UI.
# Must stay before addLangs: MUI2 requires all page macros to precede
# MUI_LANGUAGE. PAGE_INSTALL_MODE is deliberately omitted: in this build it
# would compile as a second INSTALLER mode page (assistedInstaller.nsh already
# added one); the uninstaller picks its mode from the registry in un.onInit.
!ifndef BUILD_UNINSTALLER
  !insertmacro MUI_UNPAGE_WELCOME
  !insertmacro MUI_UNPAGE_INSTFILES
  !insertmacro MUI_UNPAGE_FINISH
!endif

!insertmacro addLangs

# DETAILS PATCH 6: CHECK_APP_RUNNING declares global vars inside the macro, so
# it can only be expanded once per script, yet NSIS forbids installer code
# from calling un. functions (and vice versa). The stock flow sidesteps this
# by compiling installer and uninstaller in separate makensis passes;
# custom-script mode compiles both in ONE pass. So expand the macro exactly
# once, here for the installer side; the uninstaller side gets its own
# namespace-safe copy in uninstaller_details.nsh.
Function CheckAppRunningOnce
  !insertmacro CHECK_APP_RUNNING
FunctionEnd

# DETAILS PATCH 2: bilingual progress milestones (must come after addLangs so
# the language files are loaded before the strings are registered).
LangString detailUninstallingOld ${LANG_SIMPCHINESE} "正在卸载旧版本..."
LangString detailUninstallingOld ${LANG_ENGLISH} "Uninstalling the previous version..."
LangString detailExtracting ${LANG_SIMPCHINESE} "正在解压并复制应用程序文件..."
LangString detailExtracting ${LANG_ENGLISH} "Extracting and copying application files..."
LangString detailRegistry ${LANG_SIMPCHINESE} "正在写入注册表信息..."
LangString detailRegistry ${LANG_ENGLISH} "Writing registry entries..."
LangString detailShortcuts ${LANG_SIMPCHINESE} "正在创建快捷方式..."
LangString detailShortcuts ${LANG_ENGLISH} "Creating shortcuts..."

!ifmacrodef customHeader
  !insertmacro customHeader
!endif

Function .onInit
  Call setInstallSectionSpaceRequired

  SetOutPath $INSTDIR
  ${LogSet} on

  !ifmacrodef preInit
    !insertmacro preInit
  !endif

  !ifdef DISPLAY_LANG_SELECTOR
    !insertmacro MUI_LANGDLL_DISPLAY
  !endif

  !ifdef BUILD_UNINSTALLER
    WriteUninstaller "${UNINSTALLER_OUT_FILE}"
    !insertmacro quitSuccess
  !else
    !insertmacro check64BitAndSetRegView

    !ifdef ONE_CLICK
      !insertmacro ALLOW_ONLY_ONE_INSTALLER_INSTANCE
    !else
      ${IfNot} ${UAC_IsInnerInstance}
        !insertmacro ALLOW_ONLY_ONE_INSTALLER_INSTANCE
      ${EndIf}
    !endif

    !insertmacro initMultiUser

    !ifmacrodef customInit
      !insertmacro customInit
    !endif

    !ifmacrodef addLicenseFiles
      InitPluginsDir
      !insertmacro addLicenseFiles
    !endif
  !endif
FunctionEnd

!ifndef BUILD_UNINSTALLER
  !include "installUtil.nsh"
!endif

Section "install" INSTALL_SECTION_ID
  !ifndef BUILD_UNINSTALLER
    # If we're running a silent upgrade of a per-machine installation, elevate so extracting the new app will succeed.
    # For a non-silent install, the elevation will be triggered when the install mode is selected in the UI,
    # but that won't be executed when silent.
    !ifndef INSTALL_MODE_PER_ALL_USERS
      !ifndef ONE_CLICK
          ${if} $hasPerMachineInstallation == "1" # set in onInit by initMultiUser
          ${andIf} ${Silent}
            ${ifNot} ${UAC_IsAdmin}
              ShowWindow $HWNDPARENT ${SW_HIDE}
              !insertmacro UAC_RunElevated
              ${Switch} $0
                ${Case} 0
                  ${Break}
                ${Case} 1223 ;user aborted
                  ${Break}
                ${Default}
                  MessageBox mb_IconStop|mb_TopMost|mb_SetForeground "Unable to elevate, error $0"
                  ${Break}
              ${EndSwitch}
              Quit
            ${else}
              !insertmacro setInstallModePerAllUsers
            ${endIf}
          ${endIf}
      !endif
    !endif
    # DETAILS PATCH 1: patched section that shows real installation details.
    !include "installSection_details.nsh"
  !endif
SectionEnd

Function setInstallSectionSpaceRequired
  !insertmacro setSpaceRequired ${INSTALL_SECTION_ID}
FunctionEnd

# DETAILS PATCH 5a: the uninstall section must be compiled into the installer
# itself. Custom-script mode skips electron-builder's standalone uninstaller
# build (there is no BUILD_UNINSTALLER pass and no prebuilt uninstaller to
# embed), so include it unconditionally and let WriteUninstaller create it.
# Use the patched copy: its un.checkAppRunning shares CheckAppRunningOnce.
!include "uninstaller_details.nsh"