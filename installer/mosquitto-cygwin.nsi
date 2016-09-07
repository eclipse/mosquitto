; NSIS installer script for mosquitto

!include "MUI.nsh"

; For environment variable code
!include "WinMessages.nsh"
!define env_hklm 'HKLM "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"'

Name "mosquitto"
!define VERSION 1.4.10
OutFile "mosquitto-${VERSION}-install-cygwin.exe"

InstallDir "$PROGRAMFILES\mosquitto"

;--------------------------------
; Installer pages
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES

!define MUI_FINISHPAGE_TEXT "mosquitto has been installed on your computer.\n\nTo complete the installation you must install the dependencies described in the following readme.\n\nClick Finish to close this wizard."
!define MUI_FINISHPAGE_SHOWREADME $INSTDIR\readme-dependencies-cygwin.txt
!define MUI_FINISHPAGE_SHOWREADME_TEXT "Show dependencies readme"
!insertmacro MUI_PAGE_FINISH

;--------------------------------
; Uninstaller pages
!insertmacro MUI_UNPAGE_WELCOME
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH

;--------------------------------
; Languages

!insertmacro MUI_LANGUAGE "English"

;--------------------------------
; Installer sections

Section "Files" SecInstall
	SectionIn RO
	SetOutPath "$INSTDIR"
	;File "c:\cygwin\bin\cygwin1.dll"
	;File "c:\cygwin\bin\cyggcc_s-1.dll"
	;File "c:\cygwin\bin\cygcrypto-1.0.0.dll"
	;File "c:\cygwin\bin\cygssl-1.0.0.dll"
	;File "c:\cygwin\bin\cygz.dll"
	File "..\src\mosquitto.exe"
	File "..\build\src\Release\mosquitto_passwd.exe"
	File "..\build\client\Release\mosquitto_pub.exe"
	File "..\build\client\Release\mosquitto_sub.exe"
	File "..\build\lib\Release\mosquitto.dll"
	File "..\build\lib\cpp\Release\mosquittopp.dll"
	File "..\aclfile.example"
	File "..\ChangeLog.txt"
	File "..\mosquitto.conf"
	File "..\pwfile.example"
	File "..\readme.md"
	File "..\readme-windows.txt"
	;File "C:\pthreads\Pre-built.2\dll\x86\pthreadVC2.dll"
	;File "C:\OpenSSL-Win32\libeay32.dll"
	;File "C:\OpenSSL-Win32\ssleay32.dll"
	File "..\edl-v10"
	File "..\epl-v10"

	SetOutPath "$INSTDIR\devel"
	File "..\lib\mosquitto.h"
	File "..\build\lib\Release\mosquitto.lib"
	File "..\lib\cpp\mosquittopp.h"
	File "..\build\lib\cpp\Release\mosquittopp.lib"
	File "..\src\mosquitto_plugin.h"

	WriteUninstaller "$INSTDIR\Uninstall.exe"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\MosquittoCygwin" "DisplayName" "Mosquitto MQTT broker"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\MosquittoCygwin" "UninstallString" "$\"$INSTDIR\Uninstall.exe$\""
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\MosquittoCygwin" "QuietUninstallString" "$\"$INSTDIR\Uninstall.exe$\" /S"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\MosquittoCygwin" "HelpLink" "http://mosquitto.org/"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\MosquittoCygwin" "URLInfoAbout" "http://mosquitto.org/"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\MosquittoCygwin" "DisplayVersion" "${VERSION}"
	WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\MosquittoCygwin" "NoModify" "1"
	WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\MosquittoCygwin" "NoRepair" "1"

	WriteRegExpandStr ${env_hklm} MOSQUITTO_DIR $INSTDIR
	SendMessage ${HWND_BROADCAST} ${WM_WININICHANGE} 0 "STR:Environment" /TIMEOUT=5000
SectionEnd

Section "Service" SecService
	ExecWait '"$INSTDIR\mosquitto.exe" install'
SectionEnd

Section "Uninstall"
	ExecWait '"$INSTDIR\mosquitto.exe" uninstall'
	;Delete "$INSTDIR\cygwin1.dll"
	;Delete "$INSTDIR\cyggcc_s-1.dll"
	;Delete "$INSTDIR\cygcrypto-1.0.0.dll"
	;Delete "$INSTDIR\cygssl-1.0.0.dll"
	;Delete "$INSTDIR\cygz.dll"
	Delete "$INSTDIR\mosquitto.exe"
	Delete "$INSTDIR\mosquitto_passwd.exe"
	Delete "$INSTDIR\mosquitto_pub.exe"
	Delete "$INSTDIR\mosquitto_sub.exe"
	Delete "$INSTDIR\mosquitto.dll"
	Delete "$INSTDIR\mosquittopp.dll"
	Delete "$INSTDIR\aclfile.example"
	Delete "$INSTDIR\ChangeLog.txt"
	Delete "$INSTDIR\mosquitto.conf"
	Delete "$INSTDIR\pwfile.example"
	Delete "$INSTDIR\readme.txt"
	Delete "$INSTDIR\readme-windows.txt"
	;Delete "$INSTDIR\pthreadVC2.dll"
	;Delete "$INSTDIR\libeay32.dll"
	;Delete "$INSTDIR\ssleay32.dll"
	Delete "$INSTDIR\edl-v10"
	Delete "$INSTDIR\epl-v10"

	Delete "$INSTDIR\devel\mosquitto.h"
	Delete "$INSTDIR\devel\mosquitto.lib"
	Delete "$INSTDIR\devel\mosquittopp.h"
	Delete "$INSTDIR\devel\mosquittopp.lib"
	Delete "$INSTDIR\devel\mosquitto_plugin.h"

	Delete "$INSTDIR\Uninstall.exe"
	RMDir "$INSTDIR"
	DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\MosquittoCygwin"

	DeleteRegValue ${env_hklm} MOSQUITTO_DIR
	SendMessage ${HWND_BROADCAST} ${WM_WININICHANGE} 0 "STR:Environment" /TIMEOUT=5000
SectionEnd

LangString DESC_SecInstall ${LANG_ENGLISH} "The main installation."
LangString DESC_SecService ${LANG_ENGLISH} "Install mosquitto as a Windows service (needs all dependencies installed)?"
!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
	!insertmacro MUI_DESCRIPTION_TEXT ${SecInstall} $(DESC_SecInstall)
	!insertmacro MUI_DESCRIPTION_TEXT ${SecService} $(DESC_SecService)
!insertmacro MUI_FUNCTION_DESCRIPTION_END
