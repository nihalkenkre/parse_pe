@echo off
cl /nologo /c /GS- /W0 /Ox main.c
nasm parse_pe.asm -f win64 -o parse_pe.obj
link /nologo parse_pe.obj main.obj /machine:x64 /largeaddressaware:no /out:parse_pe.exe

del *.obj