@echo off

set NAME=malicious

if exist %NAME%.obj del %NAME%.obj
if exist %NAME%.exe del %NAME%.exe

\masm32\bin\ml /c /coff /nologo src/%NAME%.asm
\masm32\bin\link /SUBSYSTEM:WINDOWS %NAME%.obj > nul

:: DEBUG
:: \masm32\bin\ml /Zi /Zd /Zf /W3 /FR /Fm /Fl /c /coff /nologo %NAME%.asm
:: \masm32\bin\link /SECTION:.code,EWRC /DEBUG /DEBUGTYPE:CV /SUBSYSTEM:WINDOWS %NAME%.obj > nul

:: dir %NAME%.*

:: First payload needs write access
start /WAIT "" pewrite.exe %NAME%.exe

if exist %NAME%.obj del %NAME%.obj
move %NAME%.exe test\
echo %NAME%.exe is inside the folder test

pause