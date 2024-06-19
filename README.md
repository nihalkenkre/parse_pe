# parse_pe
A tool to print out different parts of a Portable Executable file, to the console.
Written in Python, C and ASM.

```
arguments:
  filepath

options:
  -h, --help            show this help message and exit
  --dos-header          Print the DOS header
  --dos-stub            Print the DOS stub
  --nt-headers          Print the NT headers
  --nt-headers-signature
                        Print the NT headers Signature
  --nt-headers-file-header
                        Print the NT headers File header
  --nt-headers-optional-header
                        Print the NT headers Optional header
  --section-headers     Print the section headers
  --exported-functions EXPORTED_FUNCTIONS
                        Print the export address table
  --imported-functions IMPORTED_FUNCTIONS
                        Print the import address table
```
