@echo off
cl /nologo /DWIN32_LEAN_AND_MEAN /DUNICODE /W3 /Ox /MT parse_pe.c /link /subsystem:console /out:parse_pe.exe
del parse_pe.obj