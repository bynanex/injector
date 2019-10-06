@echo off
setlocal
set PATH=C:\Program Files\VMProtect;C:\Program Files\VMProtect Professional;C:\Program Files\VMProtect Ultimate;%PATH%

:: VMProtect_Con File [Output File] [-pf Project File] [-sf Script File] [-lf Licensing Parameters File] [-bd Build Date (yyyy-mm-dd)] [-wm Watermark Name] [-we]
::
:: File - the file name of the executable you want to protect (*.exe, *.dll and so on), or the file name of a (*.vmp) project. If a project file name is specified, the file name of the executable is taken from the project file. 
:: Output File - the file name and path to the protected file that should be created after processing the original file. If this parameter is not set, the value is taken from the project file. 
:: Project File - the file name and path to the project file created in the GUI mode. If the parameter is not set, the program searches for a *.vmp file in the folder of the executable. 
:: Script file - the file name of the script the protected file is processed with. If the parameter is not set, the script from the current project file is used. 
:: Licensing Parameters File - the name of a file containing licensing parameters. If this parameter is not set, licensing parameters are taken from the current project file. 
:: Build Date - Application build date in the following format: "yyyy-mm-dd". If this parameter is not set, the current date is used. The build date is inscribed into the protected application and is used by the licensing system to check serial numbers against the "Maximum build date" field. 
:: Watermark Name - the name of a watermark inserted into the protected file. If the name of a watermark is not set, the watermark specified in the project settings is used.
:: we - when this parameter is set, all warnings are displayed as errors.

set INPUTFILE=
if "%~1" NEQ "" set INPUTFILE="%~1"

set OUTPUTFILE=
if "%~2" NEQ "" set OUTPUTFILE="%~2"

set PROJECTFILE="%CD%\injector.sys.vmp"
if "%~3" NEQ "" set PROJECTFILE="%~3"

echo Command: VMProtect_Con.exe %INPUTFILE% %OUTPUTFILE% -pf %PROJECTFILE%

VMProtect_Con.exe %INPUTFILE% %OUTPUTFILE% -pf %PROJECTFILE%
if not %ERRORLEVEL%==0 goto vmp_error

echo File protected successfully.
goto vmp_done

:vmp_error
echo VMProtect error occurred.

:vmp_done
endlocal
exit /B %ERRORLEVEL%
