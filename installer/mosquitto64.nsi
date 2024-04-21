; NSIS installer script for mosquitto
Unicode True
SetCompressor /SOLID lzma

!include "MUI2.nsh"
!include "nsDialogs.nsh"
!include "LogicLib.nsh"

; For environment variable code
!include "WinMessages.nsh"
!define env_hklm 'HKLM "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"'

Name "Eclipse Mosquitto"
!define VERSION 2.1.0
OutFile "mosquitto-${VERSION}-install-windows-x64.exe"

!include "x64.nsh"
InstallDir "$PROGRAMFILES64\Mosquitto"

;--------------------------------
; Installer pages
!insertmacro MUI_PAGE_WELCOME

!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
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
	File "..\build64\src\Release\mosquitto.exe"
	File "..\build64\apps\mosquitto_ctrl\Release\mosquitto_ctrl.exe"
	File "..\build64\apps\mosquitto_passwd\Release\mosquitto_passwd.exe"
	File "..\build64\client\Release\mosquitto_pub.exe"
	File "..\build64\client\Release\mosquitto_sub.exe"
	File "..\build64\client\Release\mosquitto_rr.exe"
	File "..\build64\libcommon\Release\mosquitto_common.dll"
	File "..\build64\lib\Release\mosquitto.dll"
	File "..\build64\lib\cpp\Release\mosquittopp.dll"
	File "..\build64\plugins\dynamic-security\Release\mosquitto_dynamic_security.dll"
	File "..\build64\plugins\persist-sqlite\Release\mosquitto_persist_sqlite.dll"
	File "..\build64\plugins\sparkplug-aware\Release\mosquitto_sparkplug_aware.dll"
	File "..\aclfile.example"
	File "..\ChangeLog.txt"
	File "..\mosquitto.conf"
	File "..\NOTICE.md"
	File "..\pwfile.example"
	File "..\README.md"
	File "..\README-windows.txt"
	File "..\README-letsencrypt.md"
	File "..\SECURITY.md"
	File "..\edl-v10"
	File "..\epl-v20"

	File "..\build64\vcpkg_installed\x64-windows-release\bin\cjson.dll"
	File "..\build64\vcpkg_installed\x64-windows-release\bin\libcrypto-3-x64.dll"
	File "..\build64\vcpkg_installed\x64-windows-release\bin\libssl-3-x64.dll"
	File "..\build64\vcpkg_installed\x64-windows-release\bin\pthreadVC3.dll"
	File "..\build64\vcpkg_installed\x64-windows-release\bin\sqlite3.dll"

	SetOutPath "$INSTDIR\devel"
	File "..\build64\lib\Release\mosquitto.lib"
	File "..\build64\lib\cpp\Release\mosquittopp.lib"
	File "..\include\mosquitto.h"
	File "..\include\mosquitto_broker.h"
	File "..\include\mosquitto_plugin.h"
	File "..\include\mosquittopp.h"
	file "..\include\mqtt_protocol.h"

	SetOutPath "$INSTDIR\devel\mosquitto"
	File "..\include\mosquitto\broker.h"
	File "..\include\mosquitto\broker_control.h"
	File "..\include\mosquitto\broker_plugin.h"
	File "..\include\mosquitto\defs.h"
	File "..\include\mosquitto\libcommon.h"
	File "..\include\mosquitto\libcommon_properties.h"
	File "..\include\mosquitto\libcommon_string.h"
	File "..\include\mosquitto\libcommon_topic.h"
	File "..\include\mosquitto\libcommon_utf8.h"
	File "..\include\mosquitto\libmosquitto.h"
	File "..\include\mosquitto\libmosquitto_auth.h"
	File "..\include\mosquitto\libmosquitto_callbacks.h"
	File "..\include\mosquitto\libmosquitto_connect.h"
	File "..\include\mosquitto\libmosquitto_create_delete.h"
	File "..\include\mosquitto\libmosquitto_helpers.h"
	File "..\include\mosquitto\libmosquitto_loop.h"
	File "..\include\mosquitto\libmosquitto_message.h"
	File "..\include\mosquitto\libmosquitto_options.h"
	File "..\include\mosquitto\libmosquitto_publish.h"
	File "..\include\mosquitto\libmosquitto_socks.h"
	File "..\include\mosquitto\libmosquitto_subscribe.h"
	File "..\include\mosquitto\libmosquitto_tls.h"
	File "..\include\mosquitto\libmosquitto_unsubscribe.h"
	File "..\include\mosquitto\libmosquitto_will.h"
	File "..\include\mosquitto\libmosquittopp.h"
	File "..\include\mosquitto\mqtt_protocol.h"


	WriteUninstaller "$INSTDIR\Uninstall.exe"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Mosquitto64" "DisplayName" "Eclipse Mosquitto MQTT broker (64 bit)"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Mosquitto64" "UninstallString" "$\"$INSTDIR\Uninstall.exe$\""
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Mosquitto64" "QuietUninstallString" "$\"$INSTDIR\Uninstall.exe$\" /S"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Mosquitto64" "HelpLink" "https://mosquitto.org/"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Mosquitto64" "URLInfoAbout" "https://mosquitto.org/"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Mosquitto64" "DisplayVersion" "${VERSION}"
	WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Mosquitto64" "NoModify" "1"
	WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Mosquitto64" "NoRepair" "1"

	WriteRegExpandStr ${env_hklm} MOSQUITTO_DIR $INSTDIR
	SendMessage ${HWND_BROADCAST} ${WM_WININICHANGE} 0 "STR:Environment" /TIMEOUT=5000
SectionEnd

Section "Visual Studio Runtime"
  SetOutPath "$INSTDIR"
  File "VC_redist.x64.exe"
  ExecWait '"$INSTDIR\VC_redist.x64.exe" /quiet /norestart'
  Delete "$INSTDIR\VC_redist.x64.exe"
SectionEnd

Section "Service" SecService
	ExecWait '"$INSTDIR\mosquitto.exe" install'
SectionEnd

Section "Uninstall"
	ExecWait '"$INSTDIR\mosquitto.exe" uninstall'
	Delete "$INSTDIR\mosquitto.exe"
	Delete "$INSTDIR\mosquitto_common.dll"
	Delete "$INSTDIR\mosquitto_ctrl.exe"
	Delete "$INSTDIR\mosquitto_db_dump.exe"
	Delete "$INSTDIR\mosquitto_passwd.exe"
	Delete "$INSTDIR\mosquitto_pub.exe"
	Delete "$INSTDIR\mosquitto_rr.exe"
	Delete "$INSTDIR\mosquitto_sub.exe"
	Delete "$INSTDIR\mosquitto.dll"
	Delete "$INSTDIR\mosquittopp.dll"
	Delete "$INSTDIR\mosquitto_dynamic_security.dll"
	Delete "$INSTDIR\mosquitto_persist_sqlite.dll"
	Delete "$INSTDIR\mosquitto_sparkplug_aware.dll"
	Delete "$INSTDIR\aclfile.example"
	Delete "$INSTDIR\ChangeLog.txt"
	Delete "$INSTDIR\mosquitto.conf"
	Delete "$INSTDIR\pwfile.example"
	Delete "$INSTDIR\NOTICE.md"
	Delete "$INSTDIR\README.md"
	Delete "$INSTDIR\README-windows.txt"
	Delete "$INSTDIR\README-letsencrypt.md"
	Delete "$INSTDIR\SECURITY.md"
	Delete "$INSTDIR\edl-v10"
	Delete "$INSTDIR\epl-v20"

	Delete "$INSTDIR\argon2.dll"
	Delete "$INSTDIR\cjson.dll"
	Delete "$INSTDIR\libcrypto-3-x64.dll"
	Delete "$INSTDIR\libssl-3-x64.dll"
	Delete "$INSTDIR\pthreadVC3.dll"
	Delete "$INSTDIR\sqlite3.dll"

	Delete "$INSTDIR\devel\mosquitto.h"
	Delete "$INSTDIR\devel\mosquitto/broker.h"
	Delete "$INSTDIR\devel\mosquitto/broker_control.h"
	Delete "$INSTDIR\devel\mosquitto/broker_plugin.h"
	Delete "$INSTDIR\devel\mosquitto/defs.h"
	Delete "$INSTDIR\devel\mosquitto/libcommon.h"
	Delete "$INSTDIR\devel\mosquitto/libcommon_properties.h"
	Delete "$INSTDIR\devel\mosquitto/libcommon_string.h"
	Delete "$INSTDIR\devel\mosquitto/libcommon_topic.h"
	Delete "$INSTDIR\devel\mosquitto/libcommon_utf8.h"
	Delete "$INSTDIR\devel\mosquitto/libmosquitto.h"
	Delete "$INSTDIR\devel\mosquitto/libmosquitto_auth.h"
	Delete "$INSTDIR\devel\mosquitto/libmosquitto_callbacks.h"
	Delete "$INSTDIR\devel\mosquitto/libmosquitto_connect.h"
	Delete "$INSTDIR\devel\mosquitto/libmosquitto_create_delete.h"
	Delete "$INSTDIR\devel\mosquitto/libmosquitto_helpers.h"
	Delete "$INSTDIR\devel\mosquitto/libmosquitto_loop.h"
	Delete "$INSTDIR\devel\mosquitto/libmosquitto_message.h"
	Delete "$INSTDIR\devel\mosquitto/libmosquitto_options.h"
	Delete "$INSTDIR\devel\mosquitto/libmosquitto_publish.h"
	Delete "$INSTDIR\devel\mosquitto/libmosquitto_socks.h"
	Delete "$INSTDIR\devel\mosquitto/libmosquitto_subscribe.h"
	Delete "$INSTDIR\devel\mosquitto/libmosquitto_tls.h"
	Delete "$INSTDIR\devel\mosquitto/libmosquitto_unsubscribe.h"
	Delete "$INSTDIR\devel\mosquitto/libmosquitto_will.h"
	Delete "$INSTDIR\devel\mosquitto/libmosquittopp.h"
	Delete "$INSTDIR\devel\mosquitto/mqtt_protocol.h"
	Delete "$INSTDIR\devel\mosquitto_broker.h"
	Delete "$INSTDIR\devel\mosquitto_plugin.h"
	Delete "$INSTDIR\devel\mosquittopp.h"
	Delete "$INSTDIR\devel\mqtt_protocol.h"
	RMDir "$INSTDIR\devel\mosquitto"
	RMDir "$INSTDIR\devel"

	Delete "$INSTDIR\Uninstall.exe"
	RMDir "$INSTDIR"
	DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Mosquitto64"

	DeleteRegValue ${env_hklm} MOSQUITTO_DIR
	SendMessage ${HWND_BROADCAST} ${WM_WININICHANGE} 0 "STR:Environment" /TIMEOUT=5000
SectionEnd

LangString DESC_SecInstall ${LANG_ENGLISH} "The main installation."
LangString DESC_SecService ${LANG_ENGLISH} "Install mosquitto as a Windows service?"

!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
	!insertmacro MUI_DESCRIPTION_TEXT ${SecInstall} $(DESC_SecInstall)
	!insertmacro MUI_DESCRIPTION_TEXT ${SecService} $(DESC_SecService)
!insertmacro MUI_FUNCTION_DESCRIPTION_END
