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

typedef struct my_nt_headers_file_header
{
    IMAGE_FILE_HEADER FileHeader;
    int iRetVal;
} MY_NT_HEADER_FILE_HEADER;

typedef struct my_nt_headers_optional_header
{
    IMAGE_OPTIONAL_HEADER32 OptionalHeader32;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader64;
    int iRetVal;
} MY_NT_HEADER_OPTIONAL_HEADER;

typedef struct my_section_headers
{
    IMAGE_SECTION_HEADER *SectionHeaders;
    WORD SectionCount;
    int iRetVal;
} MY_SECTION_HEADERS;

typedef enum pe_type
{
    PEType_x86,
    PEType_x86_64,
} PEType;

MY_IMAGE_DOS_HEADER parse_dos_header(HANDLE hFile)
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

MY_IMAGE_DOS_STUB parse_dos_stub(HANDLE hFile, DWORD dwStubSize)
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

MY_NT_HEADER_SIGNATURE parse_nt_headers_signature(HANDLE hFile)
{
    int iRetVal = 0;

    DWORD Signature;
    if (!ReadFile((HANDLE)hFile, &Signature, sizeof(DWORD), NULL, NULL))
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

MY_NT_HEADER_FILE_HEADER parse_nt_headers_file_header(HANDLE hFile)
{
    int iRetVal = 0;

    IMAGE_FILE_HEADER FileHeader = {0};

    if (!ReadFile((HANDLE)hFile, &FileHeader, NT_HEADER_FILE_HEADER_SIZE, NULL, NULL))
    {
        iRetVal = GetLastError();
        printf("ERR: ReadFile failed with %d\n", iRetVal);

        goto shutdown;
    }

shutdown:
    MY_NT_HEADER_FILE_HEADER MyNTHeaderFileHeader = {
        .FileHeader = FileHeader,
        .iRetVal = iRetVal,
    };
    return MyNTHeaderFileHeader;
}

void PrintNTHeadersFileHeader(IMAGE_FILE_HEADER FileHeader)
{
    printf("\n\
                NT Header File Header \n\
        Machine             : 0x%x\n\
        Section Count       : 0x%x\n\
        Time Date Stamp     : 0x%x\n\
        Sym Table Ptr       : 0x%x\n\
        Sym Count           : 0x%x\n\
        Optional Hdr Size   : 0x%x\n\
        Characteristics     : 0x%x\n\
    ",
           FileHeader.Machine, FileHeader.NumberOfSections, FileHeader.TimeDateStamp, FileHeader.PointerToSymbolTable,
           FileHeader.NumberOfSymbols, FileHeader.SizeOfOptionalHeader, FileHeader.Characteristics);
}

MY_NT_HEADER_OPTIONAL_HEADER parse_nt_headers_optional_header(HANDLE hFile, PEType ePEType, DWORD dwOptionalHeaderSize)
{
    int iRetVal = 0;

    MY_NT_HEADER_OPTIONAL_HEADER MyNTHeaderOptionalHeader;

    if (ePEType == PEType_x86)
    {
        IMAGE_OPTIONAL_HEADER32 OptionalHeader;
        if (!ReadFile(hFile, &OptionalHeader, dwOptionalHeaderSize, NULL, NULL))
        {
            iRetVal = GetLastError();
            printf("ERR: ReadFile failed with %d\n", iRetVal);

            goto shutdown;
        }

        MyNTHeaderOptionalHeader.OptionalHeader32 = OptionalHeader;
    }
    else if (ePEType == PEType_x86_64)
    {
        IMAGE_OPTIONAL_HEADER64 OptionalHeader;
        if (!ReadFile(hFile, &OptionalHeader, dwOptionalHeaderSize, NULL, NULL))
        {
            iRetVal = GetLastError();
            printf("ERR: ReadFile failed with %d\n", iRetVal);

            goto shutdown;
        }

        MyNTHeaderOptionalHeader.OptionalHeader64 = OptionalHeader;
    }

shutdown:
    MyNTHeaderOptionalHeader.iRetVal = iRetVal;

    return MyNTHeaderOptionalHeader;
}

void PrintNTHeadersOptionalHeader32(IMAGE_OPTIONAL_HEADER32 OptionalHeader)
{
    printf("\n\
                NT Header Optional Header\n\
            Magic                       : 0x%x\n\
            Major Linker Version        : 0x%x\n\
            Minor Linker Version        : 0x%x\n\
            Code Size                   : 0x%x\n\
            Initialized Data Size       : 0x%x\n\
            Unintialized Data Size      : 0x%x\n\
            Entry Point Addr            : 0x%x\n\
            Base of Code                : 0x%x\n\
            Base of Data                : 0x%x\n\
            Image Base                  : 0x%x\n\
            Section Alignment           : 0x%x\n\
            File Alignment              : 0x%x\n\
            Major OS Version            : 0x%x\n\
            Minor OS Version            : 0x%x\n\
            Major Image Version         : 0x%x\n\
            Minor Image Version         : 0x%x\n\
            Major Subsystem Version     : 0x%x\n\
            Minor Subsystem Version     : 0x%x\n\
            Win32 Version Value         : 0x%x\n\
            Size of Image               : 0x%x\n\
            Size of Headers             : 0x%x\n\
            Checksum                    : 0x%x\n\
            Subsystem                   : 0x%x\n\
            DLL Characteristics         : 0x%x\n\
            Stack Reserve Size          : 0x%x\n\
            Stack Commit Size           : 0x%x\n\
            Heap Reserve Size           : 0x%x\n\
            Heap Commit Size            : 0x%x\n\
            Loader Flags                : 0x%x\n\
            RVAs and Sizes Count        : 0x%x\n\
            Export Directory            : RVA 0x%x, Size 0x%x\n\
            Import Directory            : RVA 0x%x, Size 0x%x\n\
            Resource Directory          : RVA 0x%x, Size 0x%x\n\
            Exception Directory         : RVA 0x%x, Size 0x%x\n\
            Certificate Directory       : RVA 0x%x, Size 0x%x\n\
            Base Reloc Directory        : RVA 0x%x, Size 0x%x\n\
            Debug Directory             : RVA 0x%x, Size 0x%x\n\
            Architecture                : RVA 0x%x, Size 0x%x\n\
            Global Pointer              : RVA 0x%x, Size 0x%x\n\
            TLS Directory               : RVA 0x%x, Size 0x%x\n\
            Load Config Directory       : RVA 0x%x, Size 0x%x\n\
            Bound Import                : RVA 0x%x, Size 0x%x\n\
            IAT                         : RVA 0x%x, Size 0x%x\n\
            Delay Import Descriptor     : RVA 0x%x, Size 0x%x\n\
            CLR Header                  : RVA 0x%x, Size 0x%x\n\
            Reserved                    : RVA 0x%x, Size 0x%x\n\
    ",
           OptionalHeader.Magic, OptionalHeader.MajorLinkerVersion, OptionalHeader.MinorLinkerVersion, OptionalHeader.SizeOfCode,
           OptionalHeader.SizeOfInitializedData, OptionalHeader.SizeOfUninitializedData, OptionalHeader.AddressOfEntryPoint, OptionalHeader.BaseOfCode,
           OptionalHeader.BaseOfData, OptionalHeader.ImageBase, OptionalHeader.SectionAlignment, OptionalHeader.FileAlignment, OptionalHeader.MajorOperatingSystemVersion,
           OptionalHeader.MinorOperatingSystemVersion, OptionalHeader.MajorImageVersion, OptionalHeader.MinorImageVersion, OptionalHeader.MajorSubsystemVersion,
           OptionalHeader.MinorSubsystemVersion, OptionalHeader.Win32VersionValue, OptionalHeader.SizeOfImage, OptionalHeader.SizeOfHeaders, OptionalHeader.CheckSum,
           OptionalHeader.Subsystem, OptionalHeader.DllCharacteristics, OptionalHeader.SizeOfStackReserve, OptionalHeader.SizeOfStackCommit, OptionalHeader.SizeOfHeapReserve,
           OptionalHeader.SizeOfHeapCommit, OptionalHeader.LoaderFlags, OptionalHeader.NumberOfRvaAndSizes, OptionalHeader.DataDirectory[0].VirtualAddress, OptionalHeader.DataDirectory[0].Size,
           OptionalHeader.DataDirectory[1].VirtualAddress, OptionalHeader.DataDirectory[1].Size, OptionalHeader.DataDirectory[2].VirtualAddress, OptionalHeader.DataDirectory[2].Size,
           OptionalHeader.DataDirectory[3].VirtualAddress, OptionalHeader.DataDirectory[3].Size, OptionalHeader.DataDirectory[4].VirtualAddress, OptionalHeader.DataDirectory[4].Size,
           OptionalHeader.DataDirectory[5].VirtualAddress, OptionalHeader.DataDirectory[5].Size, OptionalHeader.DataDirectory[6].VirtualAddress, OptionalHeader.DataDirectory[6].Size,
           OptionalHeader.DataDirectory[7].VirtualAddress, OptionalHeader.DataDirectory[7].Size, OptionalHeader.DataDirectory[8].VirtualAddress, OptionalHeader.DataDirectory[8].Size,
           OptionalHeader.DataDirectory[9].VirtualAddress, OptionalHeader.DataDirectory[9].Size, OptionalHeader.DataDirectory[10].VirtualAddress, OptionalHeader.DataDirectory[10].Size,
           OptionalHeader.DataDirectory[11].VirtualAddress, OptionalHeader.DataDirectory[11].Size, OptionalHeader.DataDirectory[12].VirtualAddress, OptionalHeader.DataDirectory[12].Size,
           OptionalHeader.DataDirectory[13].VirtualAddress, OptionalHeader.DataDirectory[13].Size, OptionalHeader.DataDirectory[14].VirtualAddress, OptionalHeader.DataDirectory[14].Size,
           OptionalHeader.DataDirectory[15].VirtualAddress, OptionalHeader.DataDirectory[15].Size);
}

void PrintNTHeadersOptionalHeader64(IMAGE_OPTIONAL_HEADER64 OptionalHeader)
{
    printf("\n\
                NT Header Optional Header\n\
            Magic                       : 0x%x\n\
            Major Linker Version        : 0x%x\n\
            Minor Linker Version        : 0x%x\n\
            Code Size                   : 0x%x\n\
            Initialized Data Size       : 0x%x\n\
            Unintialized Data Size      : 0x%x\n\
            Entry Point Addr            : 0x%x\n\
            Base of Code                : 0x%x\n\
            Image Base                  : 0x%llx\n\
            Section Alignment           : 0x%x\n\
            File Alignment              : 0x%x\n\
            Major OS Version            : 0x%x\n\
            Minor OS Version            : 0x%x\n\
            Major Image Version         : 0x%x\n\
            Minor Image Version         : 0x%x\n\
            Major Subsystem Version     : 0x%x\n\
            Minor Subsystem Version     : 0x%x\n\
            Win32 Version Value         : 0x%x\n\
            Size of Image               : 0x%x\n\
            Size of Headers             : 0x%x\n\
            Checksum                    : 0x%x\n\
            Subsystem                   : 0x%x\n\
            DLL Characteristics         : 0x%x\n\
            Stack Reserve Size          : 0x%llx\n\
            Stack Commit Size           : 0x%llx\n\
            Heap Reserve Size           : 0x%llx\n\
            Heap Commit Size            : 0x%llx\n\
            Loader Flags                : 0x%x\n\
            RVAs and Sizes Count        : 0x%x\n\
            Export Directory            : RVA 0x%x, Size 0x%x\n\
            Import Directory            : RVA 0x%x, Size 0x%x\n\
            Resource Directory          : RVA 0x%x, Size 0x%x\n\
            Exception Directory         : RVA 0x%x, Size 0x%x\n\
            Certificate Directory       : RVA 0x%x, Size 0x%x\n\
            Base Reloc Directory        : RVA 0x%x, Size 0x%x\n\
            Debug Directory             : RVA 0x%x, Size 0x%x\n\
            Architecture                : RVA 0x%x, Size 0x%x\n\
            Global Pointer              : RVA 0x%x, Size 0x%x\n\
            TLS Directory               : RVA 0x%x, Size 0x%x\n\
            Load Config Directory       : RVA 0x%x, Size 0x%x\n\
            Bound Import                : RVA 0x%x, Size 0x%x\n\
            IAT                         : RVA 0x%x, Size 0x%x\n\
            Delay Import Descriptor     : RVA 0x%x, Size 0x%x\n\
            CLR Header                  : RVA 0x%x, Size 0x%x\n\
            Reserved                    : RVA 0x%x, Size 0x%x\n\
    ",
           OptionalHeader.Magic, OptionalHeader.MajorLinkerVersion, OptionalHeader.MinorLinkerVersion, OptionalHeader.SizeOfCode,
           OptionalHeader.SizeOfInitializedData, OptionalHeader.SizeOfUninitializedData, OptionalHeader.AddressOfEntryPoint, OptionalHeader.BaseOfCode,
           OptionalHeader.ImageBase, OptionalHeader.SectionAlignment, OptionalHeader.FileAlignment, OptionalHeader.MajorOperatingSystemVersion,
           OptionalHeader.MinorOperatingSystemVersion, OptionalHeader.MajorImageVersion, OptionalHeader.MinorImageVersion, OptionalHeader.MajorSubsystemVersion,
           OptionalHeader.MinorSubsystemVersion, OptionalHeader.Win32VersionValue, OptionalHeader.SizeOfImage, OptionalHeader.SizeOfHeaders, OptionalHeader.CheckSum,
           OptionalHeader.Subsystem, OptionalHeader.DllCharacteristics, OptionalHeader.SizeOfStackReserve, OptionalHeader.SizeOfStackCommit, OptionalHeader.SizeOfHeapReserve,
           OptionalHeader.SizeOfHeapCommit, OptionalHeader.LoaderFlags, OptionalHeader.NumberOfRvaAndSizes, OptionalHeader.DataDirectory[0].VirtualAddress, OptionalHeader.DataDirectory[0].Size,
           OptionalHeader.DataDirectory[1].VirtualAddress, OptionalHeader.DataDirectory[1].Size, OptionalHeader.DataDirectory[2].VirtualAddress, OptionalHeader.DataDirectory[2].Size,
           OptionalHeader.DataDirectory[3].VirtualAddress, OptionalHeader.DataDirectory[3].Size, OptionalHeader.DataDirectory[4].VirtualAddress, OptionalHeader.DataDirectory[4].Size,
           OptionalHeader.DataDirectory[5].VirtualAddress, OptionalHeader.DataDirectory[5].Size, OptionalHeader.DataDirectory[6].VirtualAddress, OptionalHeader.DataDirectory[6].Size,
           OptionalHeader.DataDirectory[7].VirtualAddress, OptionalHeader.DataDirectory[7].Size, OptionalHeader.DataDirectory[8].VirtualAddress, OptionalHeader.DataDirectory[8].Size,
           OptionalHeader.DataDirectory[9].VirtualAddress, OptionalHeader.DataDirectory[9].Size, OptionalHeader.DataDirectory[10].VirtualAddress, OptionalHeader.DataDirectory[10].Size,
           OptionalHeader.DataDirectory[11].VirtualAddress, OptionalHeader.DataDirectory[11].Size, OptionalHeader.DataDirectory[12].VirtualAddress, OptionalHeader.DataDirectory[12].Size,
           OptionalHeader.DataDirectory[13].VirtualAddress, OptionalHeader.DataDirectory[13].Size, OptionalHeader.DataDirectory[14].VirtualAddress, OptionalHeader.DataDirectory[14].Size,
           OptionalHeader.DataDirectory[15].VirtualAddress, OptionalHeader.DataDirectory[15].Size);
}

MY_SECTION_HEADERS parse_section_headers(HANDLE hFile, WORD SectionCount)
{
    int iRetVal = 0;

    IMAGE_SECTION_HEADER *SectionHeaders = (IMAGE_SECTION_HEADER *)VirtualAlloc(NULL, SectionCount * sizeof(IMAGE_SECTION_HEADER), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    if (SectionHeaders == NULL)
    {
        iRetVal = GetLastError();
        printf("ERR: parse_section_headers VirtualAlloc failed with %d\n", iRetVal);

        goto shutdown;
    }

    for (WORD id = 0; id < SectionCount; ++id)
    {
        if (!ReadFile(hFile, SectionHeaders + id, sizeof(IMAGE_SECTION_HEADER), NULL, NULL))
        {
            iRetVal = GetLastError();
            printf("ERR: parse_section_headers ReadFile failed with %d\n", GetLastError());

            goto shutdown;
        }
    }

shutdown:
    MY_SECTION_HEADERS MySectionHeaders = {
        .SectionHeaders = SectionHeaders,
        .SectionCount = SectionCount,
        .iRetVal = iRetVal,
    };

    return MySectionHeaders;
}

void PrintSectionHeaders(IMAGE_SECTION_HEADER *SectionHeaders, WORD SectionHeaderCount)
{
    printf("                    Section Headers\n");

    for (WORD id = 0; id < SectionHeaderCount; ++id)
    {
        printf("\n\
              Name                  : %s\n\
              Virtual Size          : 0x%x\n\
              Virtual Addr          : 0x%x\n\
              Raw Data Size         : 0x%x\n\
              Raw Data Pointer      : 0x%x\n\
              Reloc Pointer         : 0x%x\n\
              Line Numbers Pointer  : 0x%x\n\
              Relocs Count          : 0x%x\n\
              Line Number Count     : 0x%x\n\
              Characteristics       : 0x%x\n\
        ",
               SectionHeaders[id].Name, SectionHeaders[id].Misc.VirtualSize, SectionHeaders[id].VirtualAddress,
               SectionHeaders[id].SizeOfRawData, SectionHeaders[id].PointerToRawData, SectionHeaders[id].PointerToRelocations,
               SectionHeaders[id].PointerToLinenumbers, SectionHeaders[id].NumberOfRelocations, SectionHeaders[id].NumberOfLinenumbers,
               SectionHeaders[id].Characteristics);
    }
}

int parse_exported_functions(HANDLE hFile, int exported_function_count)
{
    int iRetVal = 0;

    return iRetVal;
}

int parse_imported_functions(HANDLE hFile, int imported_function_count)
{
    int iRetVal = 0;

    return iRetVal;
}

int parse_pe(char *sFileName, char **Options, int iOptionCount)
{
    int iRetVal = 0;

    OFSTRUCT OpenFileStruct = {0};
    HANDLE hFile = (HANDLE)OpenFile(sFileName, &OpenFileStruct, OF_READ);

    if (hFile == INVALID_HANDLE_VALUE)
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

    MY_NT_HEADER_FILE_HEADER MyNTHeaderFileHeader = parse_nt_headers_file_header(hFile);

    if (MyNTHeaderFileHeader.iRetVal != 0)
    {
        goto shutdown;
    }

    if (strcmp(Options[0], "--nt-headers-file-header") == 0)
    {
        PrintNTHeadersFileHeader(MyNTHeaderFileHeader.FileHeader);
    }

    PEType ePEType;
    if (MyNTHeaderFileHeader.FileHeader.Machine == 0x8664)
    {
        ePEType = PEType_x86_64;
    }
    else if (MyNTHeaderFileHeader.FileHeader.Machine == 0x14C)
    {
        ePEType = PEType_x86;
    }

    MY_NT_HEADER_OPTIONAL_HEADER MyNTOptionalHeader = parse_nt_headers_optional_header(hFile, ePEType, MyNTHeaderFileHeader.FileHeader.SizeOfOptionalHeader);

    if (MyNTOptionalHeader.iRetVal != 0)
    {
        goto shutdown;
    }

    if (strcmp(Options[0], "--nt-headers-optional-header") == 0)
    {
        if (ePEType == PEType_x86)
        {
            PrintNTHeadersOptionalHeader32(MyNTOptionalHeader.OptionalHeader32);
        }
        else if (ePEType = PEType_x86_64)
        {
            PrintNTHeadersOptionalHeader64(MyNTOptionalHeader.OptionalHeader64);
        }
    }

    MY_SECTION_HEADERS MySectionHeaders = parse_section_headers(hFile, MyNTHeaderFileHeader.FileHeader.NumberOfSections);

    if (MySectionHeaders.iRetVal != 0)
    {
        goto shutdown;
    }

    if (strcmp(Options[0], "--section-headers") == 0)
    {
        PrintSectionHeaders(MySectionHeaders.SectionHeaders, MySectionHeaders.SectionCount);
    }

    if (strcmp(Options[0], "--exported-functions") == 0)
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
    CloseHandle((HANDLE)hFile);

    if (MyDOSStub.Stub != NULL)
    {
        if (!VirtualFree(MyDOSStub.Stub, 0, MEM_RELEASE))
        {
            printf("ERR: Dos Stub VirtualFree failed with %d\n", GetLastError());
        }
    }

    if (MySectionHeaders.SectionHeaders != NULL)
    {
        if (!VirtualFree(MySectionHeaders.SectionHeaders, 0, MEM_RELEASE))
        {
            printf("ERR: Section Headers VirtualFree failed with %d\n", GetLastError());
        }
    }

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