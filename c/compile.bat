@echo off
cl /nologo /DWIN32_LEAN_AND_MEAN /W3 /Ox /MT parse_pe.c /link Shlwapi.lib /subsystem:console /machine:x86 /out:parse_pe.exe
del *.obj