# Patched uninstaller for KCP Proxy Client.
#
# Base: app-builder-lib@26.15.3 templates/nsis/uninstaller.nsh, copied
# verbatim except for un.checkAppRunning below. If electron-builder is
# upgraded, re-diff against the new template.
#
# In custom-script mode the installer and the embedded uninstaller compile in
# ONE makensis pass, so the stock ${GetProcessInfo}-based check cannot be
# reused here: CHECK_APP_RUNNING declares global vars inside the macro (only
# one expansion per script) and its _GetProcessInfo helper is compiled in the
# installer namespace only (NSIS forbids un. code from calling it).
#
# The uninstaller-side check below reuses the namespace-neutral FIND_PROCESS /
# KILL_PROCESS macros verbatim and fetches the current pid directly. The
# globals it reads ($CmdPath, $PowerShellPath, $IsPowerShellAvailable) are
# declared by the installer-side CHECK_APP_RUNNING expansion earlier in the
# script.
!macro UN_CHECK_APP_RUNNING
  StrCpy $CmdPath "$SYSDIR\cmd.exe"
  StrCpy $PowerShellPath "$SYSDIR\WindowsPowerShell\v1.0\powershell.exe"
  nsExec::Exec `"$PowerShellPath" -C "if (Get-Command Get-CimInstance -ErrorAction SilentlyContinue) { exit 0 } else { exit 1 }"`
  Pop $0
  ${if} $0 == 0
    nsExec::Exec `"$PowerShellPath" -C "if ((Get-ExecutionPolicy -Scope Process) -eq 'Restricted') { exit 1 } else { exit 0 }"`
    Pop $0
  ${endIf}
  ${if} $0 != 0
    StrCpy $0 1
  ${endIf}
  StrCpy $IsPowerShellAvailable $0

  # current process id, so KILL_PROCESS can exclude ourselves (the stock path
  # gets it from ${GetProcessInfo}, whose helper is installer-namespace only)
  System::Call 'kernel32::GetCurrentProcess() i.R0'
  System::Call 'Kernel32::GetProcessId(i R0) i.pid'

  ${if} ${isUpdated}
    # allow app to exit without explicit kill
    Sleep 300
  ${endIf}

  !insertmacro FIND_PROCESS "${APP_EXECUTABLE_FILENAME}" $R0
  ${if} $R0 == 0
    ${if} ${isUpdated}
      # allow app to exit without explicit kill
      Sleep 1000
      Goto unDoStopProcess
    ${endIf}
    MessageBox MB_OKCANCEL|MB_ICONEXCLAMATION "$(appRunning)" /SD IDOK IDOK unDoStopProcess
    Quit

    unDoStopProcess:

    DetailPrint "$(appClosing)"

    !insertmacro KILL_PROCESS "${APP_EXECUTABLE_FILENAME}" 0
    # to ensure that files are not "in-use"
    Sleep 300

    # Retry counter
    StrCpy $R1 0

    unLoop:
      IntOp $R1 $R1 + 1

      !insertmacro FIND_PROCESS "${APP_EXECUTABLE_FILENAME}" $R0
      ${if} $R0 == 0
        # wait to give a chance to exit gracefully
        Sleep 1000
        !insertmacro KILL_PROCESS "${APP_EXECUTABLE_FILENAME}" 1 # 1 = force kill
        !insertmacro FIND_PROCESS "${APP_EXECUTABLE_FILENAME}" $R0
        ${if} $R0 == 0
          DetailPrint `Waiting for "${PRODUCT_NAME}" to close.`
          Sleep 2000
        ${else}
          Goto unNotRunning
        ${endIf}
      ${else}
        Goto unNotRunning
      ${endIf}

      # App likely running with elevated permissions.
      # Ask user to close it manually
      ${if} $R1 > 1
        MessageBox MB_RETRYCANCEL|MB_ICONEXCLAMATION "$(appCannotBeClosed)" /SD IDCANCEL IDRETRY unLoop
        Quit
      ${else}
        Goto unLoop
      ${endIf}
    unNotRunning:
  ${endIf}
!macroend

Function un.checkAppRunning
  !insertmacro UN_CHECK_APP_RUNNING
FunctionEnd

Function un.onInit
  SetOutPath $INSTDIR
  ${LogSet} on
  
  !insertmacro check64BitAndSetRegView

  # Parse command line for /S flag and set silent mode
  ${GetParameters} $R0
  ${GetOptions} $R0 "/S" $R1
  ${IfNot} ${Errors}
    SetSilent silent
  ${EndIf}
  
  ${If} ${Silent}
    call un.checkAppRunning
  ${else}
    !ifdef ONE_CLICK
      MessageBox MB_OKCANCEL "$(areYouSureToUninstall)" IDOK +2
      Quit

      # one-click installer executes uninstall section in the silent mode, but we must show message dialog if silent mode was not explicitly set by user (using /S flag)
      call un.checkAppRunning
      SetSilent silent
    !endif
  ${endIf}

  !insertmacro initMultiUser

  !ifmacrodef customUnInit
    !insertmacro customUnInit
  !endif
FunctionEnd

Function un.atomicRMDir
  Exch $R0
  Push $R1
  Push $R2
  Push $R3

  StrCpy $R3 "$INSTDIR$R0\*.*"
  FindFirst $R1 $R2 $R3

  loop:
    StrCmp $R2 "" break

    StrCmp $R2 "." continue
    StrCmp $R2 ".." continue

    IfFileExists "$INSTDIR$R0\$R2\*.*" isDir isNotDir

    isDir:
      CreateDirectory "$PLUGINSDIR\old-install$R0\$R2"

      Push "$R0\$R2"
      Call un.atomicRMDir
      Pop $R3

      ${if} $R3 != 0
        Goto done
      ${endIf}

      Goto continue

    isNotDir:
      ClearErrors
      Rename "$INSTDIR$R0\$R2" "$PLUGINSDIR\old-install$R0\$R2"

      # Ignore errors when renaming ourselves.
      StrCmp "$R0\$R2" "${UNINSTALL_FILENAME}" 0 +2
      ClearErrors

      IfErrors 0 +3
      StrCpy $R3 "$INSTDIR$R0\$R2"
      Goto done

    continue:
      FindNext $R1 $R2
      Goto loop

  break:
    StrCpy $R3 0

  done:
    FindClose $R1

    StrCpy $R0 $R3

    Pop $R3
    Pop $R2
    Pop $R1
    Exch $R0
FunctionEnd

Function un.restoreFiles
  Exch $R0
  Push $R1
  Push $R2
  Push $R3

  StrCpy $R3 "$PLUGINSDIR\old-install$R0\*.*"
  FindFirst $R1 $R2 $R3

  loop:
    StrCmp $R2 "" break

    StrCmp $R2 "." continue
    StrCmp $R2 ".." continue

    IfFileExists "$INSTDIR$R0\$R2\*.*" isDir isNotDir

    isDir:
      CreateDirectory "$INSTDIR$R0\$R2"

      Push "$R0\$R2"
      Call un.restoreFiles
      Pop $R3

      Goto continue

    isNotDir:
      Rename "$PLUGINSDIR\old-install$R0\$R2" "$INSTDIR$R0\$R2"

    continue:
      FindNext $R1 $R2
      Goto loop

  break:
    StrCpy $R0 0
    FindClose $R1

    Pop $R3
    Pop $R2
    Pop $R1
    Exch $R0
FunctionEnd

!ifndef UNINSTALL_SECTION_NAME
  !define UNINSTALL_SECTION_NAME "Uninstall"
!endif

Section "un.${UNINSTALL_SECTION_NAME}"
  SectionIn RO
  # for assisted installer we check it here to show progress
  !ifndef ONE_CLICK
    ${IfNot} ${Silent}
      call un.checkAppRunning
    ${endIf}
  !endif

  !insertmacro setLinkVars

  !ifmacrodef customUnInstall
    !insertmacro customUnInstall
  !endif

  # delete the installed files
  !ifmacrodef customRemoveFiles
    !insertmacro customRemoveFiles
  !else
    ${if} ${isUpdated}
      CreateDirectory "$PLUGINSDIR\old-install"

      Push ""
      Call un.atomicRMDir
      Pop $R0

      ${if} $R0 != 0
        DetailPrint "File is busy, aborting: $R0"

        # Attempt to restore previous directory
        Push ""
        Call un.restoreFiles
        Pop $R0

        Abort `Can't rename "$INSTDIR" to "$PLUGINSDIR\old-install".`
      ${endif}

    ${endif}

    # Move out of $INSTDIR so it can be removed
    SetOutPath $TEMP
    # Remove all files (or remaining shallow directories from the block above)
    RMDir /r $INSTDIR
  !endif

  ${ifNot} ${isKeepShortcuts}
    WinShell::UninstAppUserModelId "${APP_ID}"

    !ifndef DO_NOT_CREATE_DESKTOP_SHORTCUT
      WinShell::UninstShortcut "$oldDesktopLink"
      Delete "$oldDesktopLink"
    !endif

    !ifndef DO_NOT_CREATE_START_MENU_SHORTCUT
      WinShell::UninstShortcut "$oldStartMenuLink"

      Delete "$oldStartMenuLink"
      ReadRegStr $R1 SHELL_CONTEXT "${INSTALL_REGISTRY_KEY}" MenuDirectory
      ${ifNot} $R1 == ""
        RMDir "$SMPROGRAMS\$R1"
      ${endIf}
    !endif
  ${endIf}

  # refresh the desktop
  System::Call 'shell32::SHChangeNotify(i, i, i, i) v (0x08000000, 0, 0, 0)'

  !ifmacrodef unregisterFileAssociations
    !insertmacro unregisterFileAssociations
  !endif

  Var /GLOBAL isDeleteAppData
  StrCpy $isDeleteAppData "0"

  ClearErrors
  ${GetParameters} $R0
  ${GetOptions} $R0 "--delete-app-data" $R1
  ${if} ${Errors}
    !ifdef DELETE_APP_DATA_ON_UNINSTALL
      ${ifNot} ${isUpdated}
        StrCpy $isDeleteAppData "1"
      ${endif}
    !endif
  ${else}
    StrCpy $isDeleteAppData "1"
  ${endIf}

  ${if} $isDeleteAppData == "1"
    # electron always uses per user app data
    ${if} $installMode == "all"
      SetShellVarContext current
    ${endif}
    RMDir /r "$APPDATA\${APP_FILENAME}"
    !ifdef APP_PRODUCT_FILENAME
      RMDir /r "$APPDATA\${APP_PRODUCT_FILENAME}"
    !endif
    # electron use package.json name for cache,indexdb etc.
    !ifdef APP_PACKAGE_NAME
      RMDir /r "$APPDATA\${APP_PACKAGE_NAME}"
    !endif
    ${if} $installMode == "all"
      SetShellVarContext all
    ${endif}
  ${endif}

  DeleteRegKey SHELL_CONTEXT "${UNINSTALL_REGISTRY_KEY}"
  !ifdef UNINSTALL_REGISTRY_KEY_2
    DeleteRegKey SHELL_CONTEXT "${UNINSTALL_REGISTRY_KEY_2}"
  !endif
  DeleteRegKey SHELL_CONTEXT "${INSTALL_REGISTRY_KEY}"

  !ifdef ONE_CLICK
    !insertmacro quitSuccess
  !endif
SectionEnd

!ifmacrodef customUnInstallSection
  !insertmacro customUnInstallSection
!endif
