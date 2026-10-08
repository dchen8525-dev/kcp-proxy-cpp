# Patched install section for KCP Proxy Client.
#
# Base: app-builder-lib@26.15.3 templates/nsis/installSection.nsh, copied
# verbatim except for the changes marked "DETAILS PATCH" below. If
# electron-builder is upgraded, re-diff against the new template.
#
# The stock template suppresses ALL status output in interactive installs
# (`SetDetailsPrint none`), which leaves the user staring at a bare progress
# bar with no copy/create/registry feedback. DETAILS PATCH 3 re-enables the
# standard NSIS details output, and DETAILS PATCH 4 adds bilingual milestones.

!include installer.nsh

InitPluginsDir

# DETAILS PATCH 3: print standard status lines (Extract:, Output folder:,
# Create shortcut:, ...) to both the status text and the details list.
SetDetailsPrint both

StrCpy $appExe "$INSTDIR\${APP_EXECUTABLE_FILENAME}"

# must be called before uninstallOldVersion
!insertmacro setLinkVars

!ifdef ONE_CLICK
  !ifdef HEADER_ICO
    File /oname=$PLUGINSDIR\installerHeaderico.ico "${HEADER_ICO}"
  !endif
  ${IfNot} ${Silent}
    !ifdef HEADER_ICO
      SpiderBanner::Show /MODERN /ICON "$PLUGINSDIR\installerHeaderico.ico"
    !else
      SpiderBanner::Show /MODERN
    !endif

    FindWindow $0 "#32770" "" $hwndparent
    FindWindow $0 "#32770" "" $hwndparent $0
    GetDlgItem $0 $0 1000
    SendMessage $0 ${WM_SETTEXT} 0 "STR:$(installing)"

    StrCpy $1 $hwndparent
		System::Call 'user32::ShutdownBlockReasonCreate(${SYSTYPE_PTR}r1, w "$(installing)")'
  ${endif}
  Call CheckAppRunningOnce
!else
  ${ifNot} ${UAC_IsInnerInstance}
    Call CheckAppRunningOnce
  ${endif}
!endif

Var /GLOBAL keepShortcuts
StrCpy $keepShortcuts "false"
!insertMacro setIsTryToKeepShortcuts
${if} $isTryToKeepShortcuts == "true"
  ReadRegStr $R1 SHELL_CONTEXT "${INSTALL_REGISTRY_KEY}" KeepShortcuts

  ${if} $R1 == "true"
  ${andIf} ${FileExists} "$appExe"
    StrCpy $keepShortcuts "true"
  ${endIf}
${endif}

# DETAILS PATCH 4: bilingual milestones around the steps the user cares about.
DetailPrint "$(detailUninstallingOld)"
!insertmacro uninstallOldVersion SHELL_CONTEXT
!insertmacro handleUninstallResult SHELL_CONTEXT

${if} $installMode == "all"
  !insertmacro uninstallOldVersion HKEY_CURRENT_USER
  !insertmacro handleUninstallResult HKEY_CURRENT_USER
${endIf}

SetOutPath $INSTDIR

!ifdef UNINSTALLER_ICON
  File /oname=uninstallerIcon.ico "${UNINSTALLER_ICON}"
!endif

# DETAILS PATCH 5c: the stock installApplicationFiles macro ends with
# `File "/oname=${UNINSTALL_FILENAME}" "${UNINSTALLER_OUT_FILE}"`, embedding
# the prebuilt standalone uninstaller. Custom-script mode skips that build
# (UNINSTALLER_OUT_FILE is never defined), so inline the macro body for the
# embedded-package case and create the uninstaller with WriteUninstaller.
DetailPrint "$(detailExtracting)"
!insertmacro extractEmbeddedAppPackage
${if} $installMode == "all"
  SetShellVarContext current
${endif}
!insertmacro copyFile "$EXEPATH" "$LOCALAPPDATA\${APP_INSTALLER_STORE_FILE}"
${if} $installMode == "all"
  SetShellVarContext all
${endif}
WriteUninstaller "${UNINSTALL_FILENAME}"
DetailPrint "$(detailRegistry)"
!insertmacro registryAddInstallInfo
DetailPrint "$(detailShortcuts)"
!insertmacro addStartMenuLink $keepShortcuts
!insertmacro addDesktopLink $keepShortcuts

${if} ${FileExists} "$newStartMenuLink"
  StrCpy $launchLink "$newStartMenuLink"
${else}
  StrCpy $launchLink "$INSTDIR\${APP_EXECUTABLE_FILENAME}"
${endIf}

!ifmacrodef registerFileAssociations
  !insertmacro registerFileAssociations
!endif

!ifmacrodef customInstall
  !insertmacro customInstall
!endif

!macro doStartApp
  # otherwise app window will be in background
  HideWindow
  !insertmacro StartApp
!macroend

!ifdef ONE_CLICK
  # https://github.com/electron-userland/electron-builder/pull/3093#issuecomment-403734568
  !ifdef RUN_AFTER_FINISH
    ${ifNot} ${Silent}
    ${orIf} ${isForceRun}
      !insertmacro doStartApp
    ${endIf}
  !else
    ${if} ${isForceRun}
      !insertmacro doStartApp
    ${endIf}
  !endif
  !insertmacro quitSuccess
!else
  # for assisted installer run only if silent, because assisted installer has run after finish option
  ${if} ${isForceRun}
  ${andIf} ${Silent}
    !insertmacro doStartApp
  ${endIf}
!endif
