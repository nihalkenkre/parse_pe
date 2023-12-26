cl /nologo /c /GS- /W0 /Ox main.c
nasm -f win64 parse_pe.asm -o parse_pe.obj
link parse_pe.obj main.obj Shlwapi.lib kernel32.lib /machine:x64 /largeaddressaware:no /out:parse_pe.exe

del *.obj