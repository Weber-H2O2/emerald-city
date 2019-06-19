@echo off

azsphere device sideload delete
REM azsphere device sideload deploy -p target\manual.imagepackage  --force
azsphere device sideload deploy -p target\manual.imagepackage
IF %ERRORLEVEL% NEQ 0 (
  echo sideload deploy command execution failed.
)
