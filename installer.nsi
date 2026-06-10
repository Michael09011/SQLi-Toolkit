!define PRODUCT_NAME "SQLi Toolkit"
!define PRODUCT_VERSION "1.0.0"
!define PRODUCT_PUBLISHER "Michael"
!define PRODUCT_URL "https://example.com"
!define COMPANY_NAME "SQLiToolkit"

Name "${PRODUCT_NAME}"
Icon "icon.ico"
OutFile "SQLiToolkit-Setup.exe"
InstallDir "$PROGRAMFILES\\${PRODUCT_NAME}"
InstallDirRegKey HKLM "Software\\${COMPANY_NAME}\\${PRODUCT_NAME}" "Install_Dir"
RequestExecutionLevel admin

Page directory
Page instfiles
UninstPage uninstConfirm
UninstPage instfiles

Section "Install"
    SetOutPath "$INSTDIR"
    File "dist\\SQLiToolkit.exe"
    CreateDirectory "$SMPROGRAMS\\${PRODUCT_NAME}"
    CreateShortCut "$DESKTOP\\${PRODUCT_NAME}.lnk" "$INSTDIR\\SQLiToolkit.exe"
    CreateShortCut "$SMPROGRAMS\\${PRODUCT_NAME}\\${PRODUCT_NAME}.lnk" "$INSTDIR\\SQLiToolkit.exe"
    WriteRegStr HKLM "Software\\${COMPANY_NAME}\\${PRODUCT_NAME}" "Install_Dir" "$INSTDIR"
    WriteUninstaller "$INSTDIR\\Uninstall.exe"
SectionEnd

Section "Uninstall"
    Delete "$INSTDIR\\SQLiToolkit.exe"
    Delete "$DESKTOP\\${PRODUCT_NAME}.lnk"
    Delete "$SMPROGRAMS\\${PRODUCT_NAME}\\${PRODUCT_NAME}.lnk"
    RMDir "$SMPROGRAMS\\${PRODUCT_NAME}"
    RMDir "$INSTDIR"
    DeleteRegKey HKLM "Software\\${COMPANY_NAME}\\${PRODUCT_NAME}"
SectionEnd
