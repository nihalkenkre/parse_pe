@echo off
cl /nologo /DWIN32_LEAN_AND_MEAN /W3 /Ox /MT parse_pe.c /link Shlwapi.lib /subsystem:console /out:parse_pe.exe
del parse_pe.obj