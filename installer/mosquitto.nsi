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
!define VERSION 2.1.2
OutFile "mosquitto-${VERSION}-install-windows-x86.exe"

InstallDir "$PROGRAMFILES\Mosquitto"

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

	ExecWait 'sc stop mosquitto'
	Sleep 1000

	SetOutPath "$INSTDIR"
	File "..\logo\mosquitto.ico"
	File "..\build\src\Release\mosquitto.exe"
	File "..\build\apps\db_dump\Release\mosquitto_db_dump.exe"
	File "..\build\apps\mosquitto_ctrl\Release\mosquitto_ctrl.exe"
	File "..\build\apps\mosquitto_passwd\Release\mosquitto_passwd.exe"
	File "..\build\apps\mosquitto_signal\Release\mosquitto_signal.exe"
	File "..\build\client\Release\mosquitto_pub.exe"
	File "..\build\client\Release\mosquitto_sub.exe"
	File "..\build\client\Release\mosquitto_rr.exe"
	File "..\build\libcommon\Release\mosquitto_common.dll"
	File "..\build\lib\Release\mosquitto.dll"
	File "..\build\lib\cpp\Release\mosquittopp.dll"
	File "..\build\plugins\acl-file\Release\mosquitto_acl_file.dll"
	File "..\build\plugins\dynamic-security\Release\mosquitto_dynamic_security.dll"
	File "..\build\plugins\password-file\Release\mosquitto_password_file.dll"
	File "..\build\plugins\persist-sqlite\Release\mosquitto_persist_sqlite.dll"
	File "..\build\plugins\sparkplug-aware\Release\mosquitto_sparkplug_aware.dll"
	File "..\aclfile.example"
	File "..\ChangeLog.txt"
	File "..\NOTICE.md"
	File "..\pskfile.example"
	File "..\pwfile.example"
	File "..\README.md"
	File "..\README-windows.txt"
	File "..\README-letsencrypt.md"
	File "..\SECURITY.md"
	File "..\edl-v10"
	File "..\epl-v20"

	SetOverwrite off
	File "..\mosquitto.conf"
	SetOverwrite on

	File "..\build\vcpkg_installed\x86-windows\bin\cjson.dll"
	File "..\build\vcpkg_installed\x86-windows\bin\libcrypto-3.dll"
	File "..\build\vcpkg_installed\x86-windows\bin\libmicrohttpd-dll.dll"
	File "..\build\vcpkg_installed\x86-windows\bin\libssl-3.dll"
	File "..\build\vcpkg_installed\x86-windows\bin\pthreadVC3.dll"
	File "..\build\vcpkg_installed\x86-windows\bin\sqlite3.dll"

	SetOutPath "$INSTDIR\devel"
	File "..\build\lib\Release\mosquitto.lib"
	File "..\build\lib\cpp\Release\mosquittopp.lib"
	File "..\build\src\Release\mosquitto_broker.lib"
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
	File "..\include\mosquitto\libcommon_base64.h"
	File "..\include\mosquitto\libcommon_cjson.h"
	File "..\include\mosquitto\libcommon_file.h"
	File "..\include\mosquitto\libcommon_memory.h"
	File "..\include\mosquitto\libcommon_password.h"
	File "..\include\mosquitto\libcommon_properties.h"
	File "..\include\mosquitto\libcommon_random.h"
	File "..\include\mosquitto\libcommon_string.h"
	File "..\include\mosquitto\libcommon_string.h"
	File "..\include\mosquitto\libcommon_time.h"
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

	SetOutPath "$INSTDIR\dashboard"
	File "..\dashboard\src\index.html"
	File "..\dashboard\src\listeners.html"

	SetOutPath "$INSTDIR\dashboard\app"
	File "..\dashboard\src\app\consts.js"
	File "..\dashboard\src\app\dashboard.js"
	File "..\dashboard\src\app\index.js"
	File "..\dashboard\src\app\listeners.js"
	File "..\dashboard\src\app\sidebar.js"

	SetOutPath "$INSTDIR\dashboard\css"
	File "..\dashboard\src\css\styles.css"

	SetOutPath "$INSTDIR\dashboard\lib"
	File "..\dashboard\src\lib\chart.umd.js"
	File "..\dashboard\src\lib\chartjs-plugin-zoom.min.js"
	File "..\dashboard\src\lib\hammer.min.js"

	SetOutPath "$INSTDIR\dashboard\media"
	File "..\dashboard\src\media\banner.svg"
	File "..\dashboard\src\media\favicon-16x16.png"
	File "..\dashboard\src\media\favicon-32x32.png"
	File "..\dashboard\src\media\mosquitto-logo.png"

	SetOutPath "$INSTDIR\dashboard\tailwind"
	File "..\dashboard\src\tailwind.config.js"
	File "..\dashboard\src\tailwind\styles.css"

	SetOutPath "$INSTDIR\dashboard\utils"
	File "..\dashboard\src\utils\assert.js"
	File "..\dashboard\src\utils\queue.js"
	File "..\dashboard\src\utils\utils.js"

	WriteUninstaller "$INSTDIR\Uninstall.exe"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Mosquitto" "DisplayName" "Eclipse Mosquitto MQTT broker (32 bit)"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Mosquitto" "DisplayIcon" "$INSTDIR\mosquitto.ico"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Mosquitto" "UninstallString" "$\"$INSTDIR\Uninstall.exe$\""
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Mosquitto" "QuietUninstallString" "$\"$INSTDIR\Uninstall.exe$\" /S"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Mosquitto" "HelpLink" "https://mosquitto.org/"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Mosquitto" "URLInfoAbout" "https://mosquitto.org/"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Mosquitto" "DisplayVersion" "${VERSION}"
	WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Mosquitto" "NoModify" "1"
	WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Mosquitto" "NoRepair" "1"

	WriteRegExpandStr ${env_hklm} MOSQUITTO_DIR $INSTDIR
	SendMessage ${HWND_BROADCAST} ${WM_WININICHANGE} 0 "STR:Environment" /TIMEOUT=5000
SectionEnd

Section "Visual Studio Runtime"
  SetOutPath "$INSTDIR"
  File "VC_redist.x86.exe"
  ExecWait '"$INSTDIR\VC_redist.x86.exe" /quiet /norestart'
  Delete "$INSTDIR\VC_redist.x86.exe"
SectionEnd

Section "Service" SecService
	ExecWait '"$INSTDIR\mosquitto.exe" install'
	ExecWait 'sc start mosquitto'
SectionEnd

Section "Uninstall"
	ExecWait 'sc stop mosquitto'
	Sleep 1000
	ExecWait '"$INSTDIR\mosquitto.exe" uninstall'
	Sleep 1000

	Delete "$INSTDIR\mosquitto.dll"
	Delete "$INSTDIR\mosquitto.exe"
	Delete "$INSTDIR\mosquitto_common.dll"
	Delete "$INSTDIR\mosquitto_ctrl.exe"
	Delete "$INSTDIR\mosquitto_db_dump.exe"
	Delete "$INSTDIR\mosquitto_passwd.exe"
	Delete "$INSTDIR\mosquitto_pub.exe"
	Delete "$INSTDIR\mosquitto_rr.exe"
	Delete "$INSTDIR\mosquitto_signal.exe"
	Delete "$INSTDIR\mosquitto_sub.exe"
	Delete "$INSTDIR\mosquittopp.dll"
	Delete "$INSTDIR\mosquitto_acl_file.dll"
	Delete "$INSTDIR\mosquitto_dynamic_security.dll"
	Delete "$INSTDIR\mosquitto_password_file.dll"
	Delete "$INSTDIR\mosquitto_persist_sqlite.dll"
	Delete "$INSTDIR\mosquitto_sparkplug_aware.dll"
	Delete "$INSTDIR\aclfile.example"
	Delete "$INSTDIR\ChangeLog.txt"
	Delete "$INSTDIR\mosquitto.conf"
	Delete "$INSTDIR\pskfile.example"
	Delete "$INSTDIR\pwfile.example"
	Delete "$INSTDIR\NOTICE.md"
	Delete "$INSTDIR\README.md"
	Delete "$INSTDIR\README-windows.txt"
	Delete "$INSTDIR\README-letsencrypt.md"
	Delete "$INSTDIR\SECURITY.md"
	Delete "$INSTDIR\edl-v10"
	Delete "$INSTDIR\epl-v20"
	Delete "$INSTDIR\mosquitto.ico"

	Delete "$INSTDIR\argon2.dll"
	Delete "$INSTDIR\cjson.dll"
	Delete "$INSTDIR\libcrypto-3.dll"
	Delete "$INSTDIR\libmicrohttpd-dll.dll"
	Delete "$INSTDIR\libssl-3.dll"
	Delete "$INSTDIR\pthreadVC3.dll"
	Delete "$INSTDIR\sqlite3.dll"

	Delete "$INSTDIR\devel\mosquitto.h"
	Delete "$INSTDIR\devel\mosquitto\broker.h"
	Delete "$INSTDIR\devel\mosquitto\broker_control.h"
	Delete "$INSTDIR\devel\mosquitto\broker_plugin.h"
	Delete "$INSTDIR\devel\mosquitto\defs.h"
	Delete "$INSTDIR\devel\mosquitto\libcommon.h"
	Delete "$INSTDIR\devel\mosquitto\libcommon_base64.h"
	Delete "$INSTDIR\devel\mosquitto\libcommon_cjson.h"
	Delete "$INSTDIR\devel\mosquitto\libcommon_file.h"
	Delete "$INSTDIR\devel\mosquitto\libcommon_memory.h"
	Delete "$INSTDIR\devel\mosquitto\libcommon_password.h"
	Delete "$INSTDIR\devel\mosquitto\libcommon_properties.h"
	Delete "$INSTDIR\devel\mosquitto\libcommon_random.h"
	Delete "$INSTDIR\devel\mosquitto\libcommon_string.h"
	Delete "$INSTDIR\devel\mosquitto\libcommon_time.h"
	Delete "$INSTDIR\devel\mosquitto\libcommon_topic.h"
	Delete "$INSTDIR\devel\mosquitto\libcommon_utf8.h"
	Delete "$INSTDIR\devel\mosquitto\libmosquitto.h"
	Delete "$INSTDIR\devel\mosquitto\libmosquitto_auth.h"
	Delete "$INSTDIR\devel\mosquitto\libmosquitto_callbacks.h"
	Delete "$INSTDIR\devel\mosquitto\libmosquitto_connect.h"
	Delete "$INSTDIR\devel\mosquitto\libmosquitto_create_delete.h"
	Delete "$INSTDIR\devel\mosquitto\libmosquitto_helpers.h"
	Delete "$INSTDIR\devel\mosquitto\libmosquitto_loop.h"
	Delete "$INSTDIR\devel\mosquitto\libmosquitto_message.h"
	Delete "$INSTDIR\devel\mosquitto\libmosquitto_options.h"
	Delete "$INSTDIR\devel\mosquitto\libmosquitto_publish.h"
	Delete "$INSTDIR\devel\mosquitto\libmosquitto_socks.h"
	Delete "$INSTDIR\devel\mosquitto\libmosquitto_subscribe.h"
	Delete "$INSTDIR\devel\mosquitto\libmosquitto_tls.h"
	Delete "$INSTDIR\devel\mosquitto\libmosquitto_unsubscribe.h"
	Delete "$INSTDIR\devel\mosquitto\libmosquitto_will.h"
	Delete "$INSTDIR\devel\mosquitto\libmosquittopp.h"
	Delete "$INSTDIR\devel\mosquitto\mqtt_protocol.h"
	Delete "$INSTDIR\devel\mosquitto_broker.h"
	Delete "$INSTDIR\devel\mosquitto_plugin.h"
	Delete "$INSTDIR\devel\mosquittopp.h"
	Delete "$INSTDIR\devel\mqtt_protocol.h"
	Delete "$INSTDIR\devel\mosquitto.lib"
	Delete "$INSTDIR\devel\mosquitto_broker.lib"
	Delete "$INSTDIR\devel\mosquittopp.lib"
	RMDir "$INSTDIR\devel\mosquitto"
	RMDir "$INSTDIR\devel"

	Delete "$INSTDIR\dashboard\app\consts.js"
	Delete "$INSTDIR\dashboard\app\dashboard.js"
	Delete "$INSTDIR\dashboard\app\index.js"
	Delete "$INSTDIR\dashboard\app\listeners.js"
	Delete "$INSTDIR\dashboard\app\sidebar.js"
	RMDir "$INSTDIR\dashboard\app"
	Delete "$INSTDIR\dashboard\css\styles.css"
	RMDir "$INSTDIR\dashboard\css"
	Delete "$INSTDIR\dashboard\index.html"
	Delete "$INSTDIR\dashboard\lib\chart.umd.js"
	Delete "$INSTDIR\dashboard\lib\chartjs-plugin-zoom.min.js"
	Delete "$INSTDIR\dashboard\lib\hammer.min.js"
	RMDir "$INSTDIR\dashboard\lib"
	Delete "$INSTDIR\dashboard\listeners.html"
	Delete "$INSTDIR\dashboard\media\banner.svg"
	Delete "$INSTDIR\dashboard\media\favicon-16x16.png"
	Delete "$INSTDIR\dashboard\media\favicon-32x32.png"
	Delete "$INSTDIR\dashboard\media\mosquitto-logo.png"
	RMDir "$INSTDIR\dashboard\media"
	Delete "$INSTDIR\dashboard\tailwind.config.js"
	Delete "$INSTDIR\dashboard\tailwind\styles.css"
	RMDir "$INSTDIR\dashboard\tailwind"
	Delete "$INSTDIR\dashboard\utils\assert.js"
	Delete "$INSTDIR\dashboard\utils\queue.js"
	Delete "$INSTDIR\dashboard\utils\utils.js"
	RMDir "$INSTDIR\dashboard\utils"
	RMDir "$INSTDIR\dashboard"

	Delete "$INSTDIR\Uninstall.exe"
	RMDir "$INSTDIR"
	DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Mosquitto"

	DeleteRegValue ${env_hklm} MOSQUITTO_DIR
	SendMessage ${HWND_BROADCAST} ${WM_WININICHANGE} 0 "STR:Environment" /TIMEOUT=5000
SectionEnd

LangString DESC_SecInstall ${LANG_ENGLISH} "The main installation."
LangString DESC_SecService ${LANG_ENGLISH} "Install mosquitto as a Windows service?"

!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
	!insertmacro MUI_DESCRIPTION_TEXT ${SecInstall} $(DESC_SecInstall)
	!insertmacro MUI_DESCRIPTION_TEXT ${SecService} $(DESC_SecService)
!insertmacro MUI_FUNCTION_DESCRIPTION_END
