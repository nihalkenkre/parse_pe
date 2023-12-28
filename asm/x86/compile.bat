cl /nologo /c /GS- /W0 /Ox main.c
nasm -f win32 parse_pe.asm -o parse_pe.obj
link parse_pe.obj main.obj kernel32.lib Shlwapi.lib /machine:x86 /out:parse_pe.exe

del *.obj