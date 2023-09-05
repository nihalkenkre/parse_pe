#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>

#include <Shlwapi.h>

#define DOS_HEADER_SIZE 64
#define NT_HEADER_SIGNATURE_SIZE 4
#define NT_HEADER_FILE_HEADER_SIZE 20

#define SECTION_HEADER_SIZE 40

#define EXPORT_DIRECTORY_SIZE 40
#define EXPORT_FUNCTION_RVA_SIZE 4
#define EXPORT_ORDINAL_SIZE 2
#define EXPORT_NAME_RVA_SIZE 4

#define IMPORT_DIRECTORY_SIZE 20
#define IMPORT_DIRECTORY_HINT_SIZE 2

#define DATA_DIRS_SIZE 120
#define SECTION_HEADER_SIZE 40

typedef struct my_image_dos_header
{
    IMAGE_DOS_HEADER DosHeader;
    int iRetVal;
} MY_IMAGE_DOS_HEADER;

typedef struct my_image_dos_stub
{
    LPVOID Stub;
    DWORD Size;
    int iRetVal;
} MY_IMAGE_DOS_STUB;

typedef struct my_nt_headers_signature
{
    DWORD Signature;
    int iRetVal;
} MY_NT_HEADER_SIGNATURE;

MY_IMAGE_DOS_HEADER parse_dos_header(HFILE hFile)
{
    int iRetVal = 0;

    IMAGE_DOS_HEADER DosHeader = {0};

    if (!ReadFile((HANDLE)hFile, &DosHeader, sizeof(DosHeader), NULL, NULL))
    {
        iRetVal = GetLastError();
        printf("ERR: ReadFile failed with %d.\n", iRetVal);

        goto shutdown;
    }

shutdown:
    MY_IMAGE_DOS_HEADER my_image_dos_header = {
        .DosHeader = DosHeader,
        .iRetVal = iRetVal,
    };
    return my_image_dos_header;
}

void PrintDOSHeader(IMAGE_DOS_HEADER DOSHeader)
{
    printf("            DOS Header\n\
    Magic Number                : %x\n\
    Bytes on Last Page          : 0x%x\n\
    Pages in file               : 0x%x\n\
    Relocations                 : 0x%x\n\
    Paragraph Header Size       : 0x%x\n\
    Min. extra paragraphs       : 0x%x\n\
    Max. extra paragraphs       : 0x%x\n\
    Initial relative SS Value   : 0x%x\n\
    Initial SP Value            : 0x%x\n\
    Checksum                    : 0x%x\n\
    Initial IP Value            : 0x%x\n\
    Intial Relative CS Value    : 0x%x\n\
    File Addr of Reloc Table    : 0x%x\n\
    Overlay Number              : 0x%x\n\
    Reserved Words              : %d %d %d %d\n\
    OEM Identifier              : 0x%x\n\
    OEM Information             : 0x%x\n\
    Reserved Words              : %d %d %d %d %d %d %d %d %d %d\n\
    File Addr New EXE Header    : 0x%x\n\
    ",
           DOSHeader.e_magic, DOSHeader.e_cblp, DOSHeader.e_cp, DOSHeader.e_crlc, DOSHeader.e_cparhdr,
           DOSHeader.e_minalloc, DOSHeader.e_maxalloc, DOSHeader.e_ss, DOSHeader.e_sp, DOSHeader.e_csum,
           DOSHeader.e_ip, DOSHeader.e_cs, DOSHeader.e_lfarlc, DOSHeader.e_ovno, DOSHeader.e_res[0], DOSHeader.e_res[1],
           DOSHeader.e_res[2], DOSHeader.e_res[3], DOSHeader.e_oemid, DOSHeader.e_oeminfo, DOSHeader.e_res2[0], DOSHeader.e_res2[1],
           DOSHeader.e_res2[2], DOSHeader.e_res2[3], DOSHeader.e_res2[4], DOSHeader.e_res2[5], DOSHeader.e_res2[6],
           DOSHeader.e_res2[7], DOSHeader.e_res2[8], DOSHeader.e_res2[9], DOSHeader.e_lfanew);
}

MY_IMAGE_DOS_STUB parse_dos_stub(HFILE hFile, DWORD dwStubSize)
{
    int iRetVal = 0;

    LPVOID DOSStubBuffer = VirtualAlloc(NULL, dwStubSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    if (DOSStubBuffer == NULL)
    {
        iRetVal = GetLastError();
        printf("ERR: VirtualAlloc failed with %d\n", iRetVal);

        goto shutdown;
    }

    if (!ReadFile((HANDLE)hFile, DOSStubBuffer, dwStubSize, NULL, NULL))
    {
        iRetVal = GetLastError();
        printf("ERR: ReadFile failed with %d\n", iRetVal);

        goto shutdown;
    }

shutdown:
    MY_IMAGE_DOS_STUB MyImageDosStub = {
        .Stub = DOSStubBuffer,
        .Size = dwStubSize,
        .iRetVal = iRetVal,
    };
    return MyImageDosStub;
}

void PrintDOSStub(LPVOID DOSStub, DWORD dwStubSize)
{
    printf("        DOS Stub\n");

    for (DWORD idx = 0; idx < dwStubSize; ++idx)
    {
        if (isprint(((unsigned char *)DOSStub)[idx]))
        {
            printf("%c", ((unsigned char *)DOSStub)[idx]);
        }
        else
        {
            printf("0x%x,", ((unsigned char *)DOSStub)[idx]);
        }
    }
}

MY_NT_HEADER_SIGNATURE parse_nt_headers_signature(HFILE hFile)
{
    int iRetVal = 0;

    DWORD Signature;
    if (!ReadFile(hFile, &Signature, sizeof(DWORD), NULL, NULL))
    {
        iRetVal = GetLastError();
        printf("ERR: ReadFile failed with %d\n", iRetVal);

        goto shutdown;
    }

shutdown:
    MY_NT_HEADER_SIGNATURE MyNTHeaderSignature = {
        .Signature = Signature,
        .iRetVal = iRetVal,
    };

    return MyNTHeaderSignature;
}

void PrintNTHeadersSignature(DWORD Signature)
{
    printf("\n\
            NT Header Signature\n\
        Signature       : %x\n\
    ",
           Signature);
}

int parse_nt_headers_file_header(HFILE hFile)
{
    int iRetVal = 0;

    return iRetVal;
}

int parse_nt_headers_optional_header(HFILE hFile)
{
    int iRetVal = 0;

    return iRetVal;
}

int parse_section_headers(HFILE hFile)
{
    int iRetVal = 0;
    return iRetVal;
}

int parse_exported_functions(HFILE hFile, int exported_function_count)
{
    int iRetVal = 0;

    return iRetVal;
}

int parse_imported_functions(HFILE hFile, int imported_function_count)
{
    int iRetVal = 0;

    return iRetVal;
}

int parse_pe(char *sFileName, char **Options, int iOptionCount)
{
    int iRetVal = 0;

    OFSTRUCT OpenFileStruct = {0};
    HFILE hFile = OpenFile(sFileName, &OpenFileStruct, OF_READ);

    if (hFile == HFILE_ERROR)
    {
        printf("Could not open %s for reading.\n", sFileName);
        iRetVal = 1;

        goto shutdown;
    }

    MY_IMAGE_DOS_HEADER MyDOSHeader = parse_dos_header(hFile);
    if (MyDOSHeader.iRetVal != 0)
    {
        goto shutdown;
    }

    if (strcmp(Options[0], "--dos-header") == 0)
    {
        PrintDOSHeader(MyDOSHeader.DosHeader);
    }

    MY_IMAGE_DOS_STUB MyDOSStub = parse_dos_stub(hFile, MyDOSHeader.DosHeader.e_lfanew - DOS_HEADER_SIZE);
    if (MyDOSStub.iRetVal != 0)
    {
        goto shutdown;
    }

    if (strcmp(Options[0], "--dos-stub") == 0)
    {
        PrintDOSStub(MyDOSStub.Stub, MyDOSStub.Size);
    }

    MY_NT_HEADER_SIGNATURE MyNTHeaderSignature = parse_nt_headers_signature(hFile);

    if (MyNTHeaderSignature.iRetVal != 0)
    {
        goto shutdown;
    }

    if (strcmp(Options[0], "--nt-headers-signature") == 0)
    {
        PrintNTHeadersSignature(MyNTHeaderSignature.Signature);
    }
    else if (strcmp(Options[0], "--nt-headers-file-header") == 0)
    {
        iRetVal = parse_nt_headers_file_header(hFile);
        if (iRetVal != 0)
        {
            goto shutdown;
        }
    }
    else if (strcmp(Options[0], "--nt-headers-optional-header") == 0)
    {
        iRetVal = parse_nt_headers_optional_header(hFile);
        if (iRetVal != 0)
        {
            goto shutdown;
        }
    }
    else if (strcmp(Options[0], "--section-headers") == 0)
    {
        iRetVal = parse_section_headers(hFile);
        if (iRetVal != 0)
        {
            goto shutdown;
        }
    }
    else if (strcmp(Options[0], "--exported-functions") == 0)
    {
        if (iOptionCount != 2)
        {
            printf("Please pass the number of exported functions to print\n");
            iRetVal = 3;

            goto shutdown;
        }
        int exported_function_count = atoi(Options[1]);

        iRetVal = parse_exported_functions(hFile, exported_function_count);

        if (iRetVal != 0)
        {
            goto shutdown;
        }
    }
    else if (strcmp(Options[0], "--imported-functions") == 0)
    {
        if (iOptionCount != 2)
        {
            printf("Please pass the number of imported functions to print\n");
            iRetVal = 4;

            goto shutdown;
        }
        int imported_function_count = atoi(Options[1]);

        iRetVal = parse_imported_functions(hFile, imported_function_count);
        if (iRetVal != 0)
        {
            goto shutdown;
        }
    }

shutdown:
    if (MyDOSStub.Stub != NULL)
    {
        if (!VirtualFree(MyDOSStub.Stub, 0, MEM_RELEASE))
        {
            printf("ERR: VirtualFree failed with %d\n", GetLastError());
        }
    }

    CloseHandle((HANDLE)hFile);
    return iRetVal;
}

int main(int argc, char **argv, char **env)
{
    int iRetVal = 0;

    if (argc == 1)
    {
        printf("Usage: parse_pe.exe <filename> <options>\n");
        iRetVal = 1;

        goto shutdown;
    }

    if (argc == 2)
    {
        if (strcmp(argv[1], "-h") == 0)
        {
            printf("Printing help\n");
            goto shutdown;
        }
        else
        {
            printf("Nothing to print here. Pass -h to list options.\n");
            iRetVal = 2;

            goto shutdown;
        }
    }

    BOOL bFileExists = PathFileExists(argv[1]);

    if (!bFileExists)
    {
        printf("ERR: Input file %s does not exist\n", argv[1]);
        iRetVal = 3;

        goto shutdown;
    }

    iRetVal = parse_pe(argv[1], argv + 2, argc - 2);
    if (iRetVal != 0)
    {
        goto shutdown;
    }

shutdown:

    return iRetVal;
}