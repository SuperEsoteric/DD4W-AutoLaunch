@ECHO OFF

NET SESSION >nul 2>&1
	IF %ERRORLEVEL% NEQ 0 (
        	ECHO Administrative privilege required. Current permissions inadequate.
		PAUSE
		EXIT
   	 ) 

REM To launch everything, you we start with this batch file.
REM This allows us to bypass the executionpolicy.

CD %~dp0
Powershell.exe -executionpolicy bypass -File Setup+Schedule_Script.ps1