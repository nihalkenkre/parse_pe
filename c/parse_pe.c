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

#define MAX_FUNCTION_NAME_LEN 256

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
    INT iRetVal;
} MY_NT_HEADER_SIGNATURE;

typedef struct my_nt_headers_file_header
{
    IMAGE_FILE_HEADER FileHeader;
    INT iRetVal;
} MY_NT_HEADER_FILE_HEADER;

typedef struct my_nt_headers_optional_header
{
    IMAGE_OPTIONAL_HEADER32 OptionalHeader32;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader64;
    INT iRetVal;
} MY_NT_HEADER_OPTIONAL_HEADER;

typedef struct my_section_headers
{
    IMAGE_SECTION_HEADER *SectionHeaders;
    WORD SectionHeadersCount;
    int iRetVal;
} MY_SECTION_HEADERS;

typedef struct my_export_directory
{
    IMAGE_EXPORT_DIRECTORY ExportDirectory;

    DWORD *Offsets;
    DWORD *FunctionRVAs;
    CHAR **Forwarders;
    WORD *Ordinals;
    DWORD *NameRVAs;
    CHAR **Names;

    INT iExportedFunctionsCount;
    INT iRetVal;
} MY_EXPORT_DIRECTORY;

typedef struct hint_name_table_entry
{
    WORD Hint;
    CHAR *Name;
} HINT_NAME_TABLE_ENTRY;

typedef struct my_import_directory
{
    IMAGE_IMPORT_DESCRIPTOR ImportDirectory;

    CHAR *sName;

    DWORD *ImportLookupTable;

    INT iImportedFunctionCount;
    INT iRetVal;
} MY_IMPORT_DIRECTORY;

typedef enum pe_type
{
    PEType_x86,
    PEType_x86_64,
} PEType;

LONG RVAToOffset(LONG rva, IMAGE_SECTION_HEADER *SectionHeaders, WORD SectionHeadersCount)
{
    for (WORD id = 0; id < SectionHeadersCount; ++id)
    {
        LONG x = SectionHeaders[id].VirtualAddress + SectionHeaders[id].SizeOfRawData;

        if (x >= rva)
        {
            return rva - SectionHeaders[id].VirtualAddress + SectionHeaders[id].PointerToRawData;
        }
    }

    return -1;
}

CHAR *GetStringFromFile(HANDLE hFile)
{
    CHAR cNameChar;

    if (!ReadFile(hFile, &cNameChar, 1, NULL, NULL))
    {
        printf("ERR: ReadFile failed with %d\n", GetLastError());
        return NULL;
    }

    CHAR *sName = VirtualAlloc(NULL, MAX_FUNCTION_NAME_LEN, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    if (sName == NULL)
    {
        printf("ERR: VirtualAlloc failed with %d\n", GetLastError());
        return NULL;
    }

    for (UINT c = 0; c < MAX_FUNCTION_NAME_LEN; ++c)
    {
        if (cNameChar != 0)
        {
            sName[c] = cNameChar;

            if (!ReadFile(hFile, &cNameChar, 1, NULL, NULL))
            {
                printf("ERR: ReadFile failed with %d\n", GetLastError());
                return NULL;
            }
        }
        else
        {
            break;
        }
    }

    return sName;
}

BOOL IsImportDirectoryZero(IMAGE_IMPORT_DESCRIPTOR ImportDirectory)
{
    return ImportDirectory.OriginalFirstThunk == 0 &&
           ImportDirectory.TimeDateStamp == 0 &&
           ImportDirectory.ForwarderChain == 0 &&
           ImportDirectory.Name == 0 &&
           ImportDirectory.FirstThunk == 0;
}

MY_IMAGE_DOS_HEADER ParseDOSHeader(HANDLE hFile)
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

MY_IMAGE_DOS_STUB ParseDOSStub(HANDLE hFile, DWORD dwStubSize)
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

MY_NT_HEADER_SIGNATURE ParseNTHeadersSignature(HANDLE hFile)
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

MY_NT_HEADER_FILE_HEADER ParseNTHeadersFileHeader(HANDLE hFile)
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

MY_NT_HEADER_OPTIONAL_HEADER ParseNTHeadersOptionalHeader(HANDLE hFile, PEType ePEType, DWORD dwOptionalHeaderSize)
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

MY_SECTION_HEADERS parse_section_headers(HANDLE hFile, WORD SectionHeadersCount)
{
    int iRetVal = 0;

    IMAGE_SECTION_HEADER *SectionHeaders = (IMAGE_SECTION_HEADER *)VirtualAlloc(NULL, SectionHeadersCount * sizeof(IMAGE_SECTION_HEADER), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    if (SectionHeaders == NULL)
    {
        iRetVal = GetLastError();
        printf("ERR: parse_section_headers VirtualAlloc failed with %d\n", iRetVal);

        goto shutdown;
    }

    for (WORD id = 0; id < SectionHeadersCount; ++id)
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
        .SectionHeadersCount = SectionHeadersCount,
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

MY_EXPORT_DIRECTORY ParseExportDirectory(HANDLE hFile, IMAGE_DATA_DIRECTORY ImageExportDirectory, INT iExportedFunctionCount, IMAGE_SECTION_HEADER *SectionHeaders, WORD SectionHeadersCount)
{
    INT iRetVal = 0;

    LONG lExportDirectoryOffset = RVAToOffset(ImageExportDirectory.VirtualAddress, SectionHeaders, SectionHeadersCount);

    DWORD dwFilePtr = SetFilePointer(hFile, lExportDirectoryOffset, NULL, FILE_BEGIN);
    if (dwFilePtr == INVALID_SET_FILE_POINTER)
    {
        iRetVal = GetLastError();
        printf("ERR: SetFilePointer failed with %d\n", iRetVal);

        goto shutdown;
    }

    MY_EXPORT_DIRECTORY MyExportDirectory;
    MyExportDirectory.iExportedFunctionsCount = iExportedFunctionCount;

    if (!ReadFile(hFile, &MyExportDirectory.ExportDirectory, sizeof(MyExportDirectory.ExportDirectory), NULL, NULL))
    {
        iRetVal = GetLastError();
        printf("ERR: ReadFile failed with %d\n", iRetVal);

        goto shutdown;
    }

    MyExportDirectory.Offsets = (DWORD *)VirtualAlloc(NULL, sizeof(DWORD) * iExportedFunctionCount, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (MyExportDirectory.Offsets == NULL)
    {
        iRetVal = GetLastError();
        printf("ERR: VirtualAlloc failed with %d\n", iRetVal);

        goto shutdown;
    }

    MyExportDirectory.FunctionRVAs = (DWORD *)VirtualAlloc(NULL, sizeof(DWORD) * iExportedFunctionCount, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (MyExportDirectory.FunctionRVAs == NULL)
    {
        iRetVal = GetLastError();
        printf("ERR: VirtualAlloc failed with %d\n", iRetVal);

        goto shutdown;
    }

    MyExportDirectory.Forwarders = (CHAR **)VirtualAlloc(NULL, sizeof(CHAR *) * iExportedFunctionCount, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (MyExportDirectory.Forwarders == NULL)
    {
        iRetVal = GetLastError();
        printf("ERR: VirtualAlloc failed with %d\n", iRetVal);

        goto shutdown;
    }

    MyExportDirectory.Ordinals = (WORD *)VirtualAlloc(NULL, sizeof(WORD) * iExportedFunctionCount, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    if (MyExportDirectory.Ordinals == NULL)
    {
        iRetVal = GetLastError();
        printf("ERR: VirtualAlloc failed with %d\n", iRetVal);

        goto shutdown;
    }

    MyExportDirectory.NameRVAs = (DWORD *)VirtualAlloc(NULL, sizeof(DWORD) * iExportedFunctionCount, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    if (MyExportDirectory.NameRVAs == NULL)
    {
        iRetVal = GetLastError();
        printf("ERR: VirtualAlloc failed with %d\n", iRetVal);

        goto shutdown;
    }
    MyExportDirectory.Names = (CHAR **)VirtualAlloc(NULL, sizeof(CHAR *) * iExportedFunctionCount, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    if (MyExportDirectory.Names == NULL)
    {
        iRetVal = GetLastError();
        printf("ERR: VirtualAlloc failed with %d\n", iRetVal);

        goto shutdown;
    }

    for (int f = 0; f < iExportedFunctionCount; ++f)
    {
        DWORD dwFunctionRVA = MyExportDirectory.ExportDirectory.AddressOfFunctions + (f * EXPORT_FUNCTION_RVA_SIZE);
        LONG lFunctionRVAOffset = RVAToOffset(dwFunctionRVA, SectionHeaders, SectionHeadersCount);

        MyExportDirectory.Offsets[f] = lFunctionRVAOffset;

        DWORD dwFilePtr = SetFilePointer(hFile, lFunctionRVAOffset, NULL, FILE_BEGIN);
        if (dwFilePtr == INVALID_SET_FILE_POINTER)
        {
            iRetVal = GetLastError();
            printf("ERR: SetFilePointer failed at FunctionRVAOffset with %d, Distance: %ld\n", iRetVal, lFunctionRVAOffset);

            goto shutdown;
        }

        if (!ReadFile(hFile, MyExportDirectory.FunctionRVAs + f, EXPORT_FUNCTION_RVA_SIZE, NULL, NULL))
        {
            iRetVal = GetLastError();
            printf("ERR: ReadFile failed with %d\n", iRetVal);

            goto shutdown;
        }

        LONG lFunctionOffset = RVAToOffset(MyExportDirectory.FunctionRVAs[f], SectionHeaders, SectionHeadersCount);

        if ((lFunctionOffset > RVAToOffset(ImageExportDirectory.VirtualAddress, SectionHeaders, SectionHeadersCount)) &&
            (lFunctionOffset < RVAToOffset(ImageExportDirectory.VirtualAddress + ImageExportDirectory.Size, SectionHeaders, SectionHeadersCount)))
        {
            dwFilePtr = SetFilePointer(hFile, lFunctionOffset, NULL, FILE_BEGIN);
            if (dwFilePtr == INVALID_SET_FILE_POINTER)
            {
                iRetVal = GetLastError();
                printf("ERR: SetFilePointer failed at FunctionOffset with %d, Distance %d\n", iRetVal, lFunctionOffset);

                goto shutdown;
            }

            MyExportDirectory.Forwarders[f] = GetStringFromFile(hFile);
        }
        else
        {
            MyExportDirectory.Forwarders[f] = "";
        }

        LONG lOrdinalsRVAOffset = RVAToOffset(MyExportDirectory.ExportDirectory.AddressOfNameOrdinals + (f * EXPORT_ORDINAL_SIZE), SectionHeaders, SectionHeadersCount);

        dwFilePtr = SetFilePointer(hFile, lOrdinalsRVAOffset, NULL, FILE_BEGIN);
        if (dwFilePtr == INVALID_SET_FILE_POINTER)
        {
            iRetVal = GetLastError();
            printf("ERR: SetFilePointer failed at OrdinalsRVAOffset with %d, Distance: %d\n", iRetVal, lOrdinalsRVAOffset);

            goto shutdown;
        }

        if (!ReadFile(hFile, &MyExportDirectory.Ordinals[f], EXPORT_ORDINAL_SIZE, NULL, NULL))
        {
            iRetVal = GetLastError();
            printf("ERR: ReadFile failed with %d\n", iRetVal);

            goto shutdown;
        }
        MyExportDirectory.Ordinals[f] += MyExportDirectory.ExportDirectory.Base;

        LONG lNameRVAOffset = RVAToOffset(MyExportDirectory.ExportDirectory.AddressOfNames + (f * EXPORT_NAME_RVA_SIZE), SectionHeaders, SectionHeadersCount);

        dwFilePtr = SetFilePointer(hFile, lNameRVAOffset, NULL, FILE_BEGIN);
        if (dwFilePtr == INVALID_SET_FILE_POINTER)
        {
            iRetVal = GetLastError();
            printf("ERR: SetFilePointer failed at NameRVAOffset with %d, Distance: %d\n", iRetVal, lNameRVAOffset);

            goto shutdown;
        }

        if (!ReadFile(hFile, &MyExportDirectory.NameRVAs[f], EXPORT_NAME_RVA_SIZE, NULL, NULL))
        {
            iRetVal = GetLastError();
            printf("ERR: ReadFile failed with %d\n", iRetVal);

            goto shutdown;
        }

        LONG lNameOffset = RVAToOffset(MyExportDirectory.NameRVAs[f], SectionHeaders, SectionHeadersCount);

        dwFilePtr = SetFilePointer(hFile, lNameOffset, NULL, FILE_BEGIN);
        if (dwFilePtr == INVALID_SET_FILE_POINTER)
        {
            iRetVal = GetLastError();
            printf("ERR: SetFilePointer failed at NameOffset with %d, Distance: %d\n", iRetVal, lNameOffset);

            goto shutdown;
        }

        CHAR *sName = GetStringFromFile(hFile);
        *(MyExportDirectory.Names + f) = sName;

        printf("%s\n", *(MyExportDirectory.Names + f));
    }

shutdown:

    MyExportDirectory.iRetVal = iRetVal;

    return MyExportDirectory;
}

void PrintExportDirectory(MY_EXPORT_DIRECTORY MyExportDirectory)
{
    printf("\n\
                Exported Functions\n\
        Characteristics             : 0x%x\n\
        Time Date Stamp             : 0x%x\n\
        Major Version               : 0x%x\n\
        Minor Version               : 0x%x\n\
        Name RVA                    : 0x%x\n\
        Ordinal Base                : 0x%x\n\
        Addr Table Entries          : 0x%x\n\
        Name Pointers Count         : 0x%x\n\
        Export Addr Table RVA       : 0x%x\n\
        Name Pointer RVA            : 0x%x\n\
        Ordinal Table RVA           : 0x%x\n\
    ",
           MyExportDirectory.ExportDirectory.Characteristics, MyExportDirectory.ExportDirectory.TimeDateStamp,
           MyExportDirectory.ExportDirectory.MajorVersion, MyExportDirectory.ExportDirectory.MinorVersion,
           MyExportDirectory.ExportDirectory.Name, MyExportDirectory.ExportDirectory.Base,
           MyExportDirectory.ExportDirectory.NumberOfFunctions, MyExportDirectory.ExportDirectory.NumberOfNames,
           MyExportDirectory.ExportDirectory.AddressOfFunctions, MyExportDirectory.ExportDirectory.AddressOfNames,
           MyExportDirectory.ExportDirectory.AddressOfNameOrdinals);

    printf("\n\n");
    printf("Offset     Ordinal    Function RVA        Name RVA                  Name                                Forwarder\n");

    for (int f = 0; f < MyExportDirectory.iExportedFunctionsCount; ++f)
    {
        printf("0x%x     0x%02x         0x%05x          0x%x           %30s          %s\n", MyExportDirectory.Offsets[f], MyExportDirectory.Ordinals[f], MyExportDirectory.FunctionRVAs[f], MyExportDirectory.NameRVAs[f], *(MyExportDirectory.Names + f), *(MyExportDirectory.Forwarders + f));
    }
}

MY_IMPORT_DIRECTORY ParseImportDirectory(HANDLE hFile, PEType ePEType, IMAGE_DATA_DIRECTORY ImageImportDirectory, INT iImportedFunctionCount, IMAGE_SECTION_HEADER *SectionHeaders, WORD SectionHeaderCount)
{
    INT iRetVal = 0;

    LONG lImportDirectoryOffset = RVAToOffset(ImageImportDirectory.VirtualAddress, SectionHeaders, SectionHeaderCount);

    DWORD dwFilePtr = SetFilePointer(hFile, lImportDirectoryOffset, NULL, FILE_BEGIN);
    if (dwFilePtr == INVALID_SET_FILE_POINTER)
    {
        iRetVal = GetLastError();
        printf("ERR: SetFilePointer failed with %d\n", iRetVal);

        goto shutdown;
    }

    MY_IMPORT_DIRECTORY MyImportDirectory = {
        .iImportedFunctionCount = iImportedFunctionCount,
    };

    if (!ReadFile(hFile, &MyImportDirectory.ImportDirectory, sizeof(MyImportDirectory.ImportDirectory), NULL, NULL))
    {
        iRetVal = GetLastError();
        printf("ERR: ReadFile failed with %d\n", iRetVal);

        goto shutdown;
    }

    if (IsImportDirectoryZero(MyImportDirectory.ImportDirectory))
    {
        goto shutdown;
    }

    LONG lNameOffset = RVAToOffset(MyImportDirectory.ImportDirectory.Name, SectionHeaders, SectionHeaderCount);

    dwFilePtr = SetFilePointer(hFile, lNameOffset, NULL, FILE_BEGIN);
    if (dwFilePtr == INVALID_SET_FILE_POINTER)
    {
        iRetVal = GetLastError();
        printf("ERR: SetFilePointer failed with %d\n", iRetVal);

        goto shutdown;
    }

    MyImportDirectory.sName = GetStringFromFile(hFile);

    DWORD ImportLookupTableEntrySize = 0;
    DWORD64 dwOrdinalNameFlagMask = 0;

    if (ePEType == PEType_x86)
    {
        ImportLookupTableEntrySize = 4;
        dwOrdinalNameFlagMask = 0x80000000;
    }
    else if (ePEType == PEType_x86_64)
    {
        ImportLookupTableEntrySize = 8;
        dwOrdinalNameFlagMask = 0x8000000000000000;
    }

    MyImportDirectory.ImportLookupTable = (DWORD *)VirtualAlloc(NULL, ImportLookupTableEntrySize * iImportedFunctionCount, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (MyImportDirectory.ImportLookupTable == NULL)
    {
        iRetVal = GetLastError();
        printf("ERR: VirtualAlloc failed with %d\n", iRetVal);

        goto shutdown;
    }

    for (INT f = 0; f < iImportedFunctionCount; ++f)
    {
        DWORD lImportLookupTableEntryRVA = MyImportDirectory.ImportDirectory.OriginalFirstThunk + (ImportLookupTableEntrySize * f);
        LONG lImportLookupTableEntryOffset = RVAToOffset(lImportLookupTableEntryRVA, SectionHeaders, SectionHeaderCount);

        dwFilePtr = SetFilePointer(hFile, lImportLookupTableEntryOffset, NULL, FILE_BEGIN);
        if (dwFilePtr == INVALID_SET_FILE_POINTER)
        {
            iRetVal = GetLastError();
            printf("ERR: SetFilePointer failed with %d\n", iRetVal);

            goto shutdown;
        }

        if (!ReadFile(hFile, MyImportDirectory.ImportLookupTable + f, ImportLookupTableEntrySize, NULL, NULL))
        {
            iRetVal = GetLastError();
            printf("ERR: ReadFile failed with %d\n", iRetVal);

            goto shutdown;
        }

        if (MyImportDirectory.ImportLookupTable[f] != 0)
        {
            DWORD64 dwOrdinalNameFlag = MyImportDirectory.ImportLookupTable[f] & dwOrdinalNameFlagMask;

            if (dwOrdinalNameFlag != dwOrdinalNameFlagMask)
            {
                DWORD dwHintNameTableEntryRVA = MyImportDirectory.ImportLookupTable[f] & 0x7fffffff;
                LONG lHintNameTableEntryOffset = RVAToOffset(dwHintNameTableEntryRVA, SectionHeaders, SectionHeaderCount);

                dwFilePtr = SetFilePointer(hFile, lHintNameTableEntryOffset, NULL, FILE_BEGIN);
                if (dwFilePtr == INVALID_SET_FILE_POINTER)
                {
                    iRetVal = GetLastError();
                    printf("ERR: SetFilePointer failed with %d\n", iRetVal);

                    goto shutdown;
                }
            }
            else
            {
            }
        }
        else
        {
            goto shutdown;
        }
    }

shutdown:
    MyImportDirectory.iRetVal = iRetVal;

    return MyImportDirectory;
}

void PrintImportDirectory(MY_IMPORT_DIRECTORY MyImportDirectory)
{
    printf("        Import Directory - %s\n", MyImportDirectory.sName);
    printf("\n\
        Import Lookup Table RVA     : 0x%x\n\
        Time/Date Stamp             : 0x%x\n\
        Forwarder Chain             : 0x%x\n\
        Name RVA                    : 0x%x\n\
        Import Addr Table RVA       : 0x%x\n",
           MyImportDirectory.ImportDirectory.OriginalFirstThunk,
           MyImportDirectory.ImportDirectory.TimeDateStamp, MyImportDirectory.ImportDirectory.ForwarderChain,
           MyImportDirectory.ImportDirectory.Name, MyImportDirectory.ImportDirectory.FirstThunk);

    printf("Original Thunk\n");

    for (INT f = 0; f < MyImportDirectory.iImportedFunctionCount; ++f)
    {
        printf("    0x%05x\n", MyImportDirectory.ImportLookupTable[f]);
    }
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

    MY_IMAGE_DOS_HEADER MyDOSHeader = ParseDOSHeader(hFile);
    if (MyDOSHeader.iRetVal != 0)
    {
        goto shutdown;
    }

    if (strcmp(Options[0], "--dos-header") == 0)
    {
        PrintDOSHeader(MyDOSHeader.DosHeader);
    }

    MY_IMAGE_DOS_STUB MyDOSStub = ParseDOSStub(hFile, MyDOSHeader.DosHeader.e_lfanew - DOS_HEADER_SIZE);
    if (MyDOSStub.iRetVal != 0)
    {
        goto shutdown;
    }

    if (strcmp(Options[0], "--dos-stub") == 0)
    {
        PrintDOSStub(MyDOSStub.Stub, MyDOSStub.Size);
    }

    MY_NT_HEADER_SIGNATURE MyNTHeaderSignature = ParseNTHeadersSignature(hFile);

    if (MyNTHeaderSignature.iRetVal != 0)
    {
        goto shutdown;
    }

    if (strcmp(Options[0], "--nt-headers-signature") == 0)
    {
        PrintNTHeadersSignature(MyNTHeaderSignature.Signature);
    }

    MY_NT_HEADER_FILE_HEADER MyNTHeaderFileHeader = ParseNTHeadersFileHeader(hFile);

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

    MY_NT_HEADER_OPTIONAL_HEADER MyNTOptionalHeader = ParseNTHeadersOptionalHeader(hFile, ePEType, MyNTHeaderFileHeader.FileHeader.SizeOfOptionalHeader);

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
        PrintSectionHeaders(MySectionHeaders.SectionHeaders, MySectionHeaders.SectionHeadersCount);
    }

    if (strcmp(Options[0], "--exported-functions") == 0)
    {
        if (iOptionCount != 2)
        {
            printf("Please pass the number of exported functions to print\n");
            iRetVal = 3;

            goto shutdown;
        }

        int iExportedFunctionCount = atoi(Options[1]);

        if (ePEType == PEType_x86)
        {
            MY_EXPORT_DIRECTORY MyExportDirectory = ParseExportDirectory(hFile, MyNTOptionalHeader.OptionalHeader32.DataDirectory[0], iExportedFunctionCount, MySectionHeaders.SectionHeaders, MySectionHeaders.SectionHeadersCount);
            if (MyExportDirectory.iRetVal != 0)
            {
                goto shutdown;
            }
            PrintExportDirectory(MyExportDirectory);

            if (MyExportDirectory.Offsets != NULL)
            {
                if (!VirtualFree(MyExportDirectory.Offsets, 0, MEM_RELEASE))
                {
                    iRetVal = GetLastError();
                    printf("ERR: VirtualFree failed with %d\n", iRetVal);

                    goto shutdown;
                }
            }

            if (MyExportDirectory.FunctionRVAs != NULL)
            {
                if (!VirtualFree(MyExportDirectory.FunctionRVAs, 0, MEM_RELEASE))
                {
                    iRetVal = GetLastError();
                    printf("ERR: VirtualFree failed with %d\n", iRetVal);

                    goto shutdown;
                }
            }

            if (MyExportDirectory.Forwarders != NULL)
            {
                for (INT f = 0; f < iExportedFunctionCount; ++f)
                {
                    if (!VirtualFree(MyExportDirectory.Forwarders + f, 0, MEM_RELEASE))
                    {
                        iRetVal = GetLastError();
                        printf("ERR: VirtualFree failed with %d\n", iRetVal);

                        goto shutdown;
                    }
                }

                if (!VirtualFree(MyExportDirectory.Forwarders, 0, MEM_RELEASE))
                {
                    iRetVal = GetLastError();
                    printf("ERR: VirtualFree failed with %d\n", iRetVal);

                    goto shutdown;
                }
            }

            if (MyExportDirectory.Ordinals != NULL)
            {
                if (!VirtualFree(MyExportDirectory.Ordinals, 0, MEM_RELEASE))
                {
                    iRetVal = GetLastError();
                    printf("ERR: VirtualFree failed with %d\n", iRetVal);

                    goto shutdown;
                }
            }

            if (MyExportDirectory.NameRVAs != NULL)
            {
                if (!VirtualFree(MyExportDirectory.NameRVAs, 0, MEM_RELEASE))
                {
                    iRetVal = GetLastError();
                    printf("ERR: VirtualFree failed with %d\n", iRetVal);

                    goto shutdown;
                }
            }

            if (MyExportDirectory.Names != NULL)
            {
                for (INT f = 0; f < iExportedFunctionCount; ++f)
                {
                    if (!VirtualFree(MyExportDirectory.Names + f, 0, MEM_RELEASE))
                    {
                        iRetVal = GetLastError();
                        printf("ERR: VirtualFree failed with %d\n", iRetVal);

                        goto shutdown;
                    }
                }

                if (!VirtualFree(MyExportDirectory.Names, 0, MEM_RELEASE))
                {
                    iRetVal = GetLastError();
                    printf("ERR: VirtualFree failed with %d\n", iRetVal);

                    goto shutdown;
                }
            }
        }
        else if (ePEType == PEType_x86_64)
        {
            MY_EXPORT_DIRECTORY MyExportDirectory = ParseExportDirectory(hFile, MyNTOptionalHeader.OptionalHeader64.DataDirectory[0], iExportedFunctionCount, MySectionHeaders.SectionHeaders, MySectionHeaders.SectionHeadersCount);
            if (MyExportDirectory.iRetVal != 0)
            {
                goto shutdown;
            }
            PrintExportDirectory(MyExportDirectory);

            if (MyExportDirectory.Offsets != NULL)
            {
                if (!VirtualFree(MyExportDirectory.Offsets, 0, MEM_RELEASE))
                {
                    iRetVal = GetLastError();
                    printf("ERR: VirtualFree failed with %d\n", iRetVal);

                    goto shutdown;
                }
            }

            if (MyExportDirectory.FunctionRVAs != NULL)
            {
                if (!VirtualFree(MyExportDirectory.FunctionRVAs, 0, MEM_RELEASE))
                {
                    iRetVal = GetLastError();
                    printf("ERR: VirtualFree failed with %d\n", iRetVal);

                    goto shutdown;
                }
            }

            if (MyExportDirectory.Forwarders != NULL)
            {
                for (INT f = 0; f < iExportedFunctionCount; ++f)
                {
                    if (!VirtualFree(MyExportDirectory.Forwarders + f, 0, MEM_RELEASE))
                    {
                        iRetVal = GetLastError();
                        printf("ERR: VirtualFree failed with %d\n", iRetVal);

                        goto shutdown;
                    }
                }

                if (!VirtualFree(MyExportDirectory.Forwarders, 0, MEM_RELEASE))
                {
                    iRetVal = GetLastError();
                    printf("ERR: VirtualFree failed with %d\n", iRetVal);

                    goto shutdown;
                }
            }

            if (MyExportDirectory.Ordinals != NULL)
            {
                if (!VirtualFree(MyExportDirectory.Ordinals, 0, MEM_RELEASE))
                {
                    iRetVal = GetLastError();
                    printf("ERR: VirtualFree failed with %d\n", iRetVal);

                    goto shutdown;
                }
            }

            if (MyExportDirectory.NameRVAs != NULL)
            {
                if (!VirtualFree(MyExportDirectory.NameRVAs, 0, MEM_RELEASE))
                {
                    iRetVal = GetLastError();
                    printf("ERR: VirtualFree failed with %d\n", iRetVal);

                    goto shutdown;
                }
            }

            if (MyExportDirectory.Names != NULL)
            {
                for (INT f = 0; f < iExportedFunctionCount; ++f)
                {
                    if (!VirtualFree(MyExportDirectory.Names + f, 0, MEM_RELEASE))
                    {
                        iRetVal = GetLastError();
                        printf("ERR: VirtualFree failed with %d\n", iRetVal);

                        goto shutdown;
                    }
                }

                if (!VirtualFree(MyExportDirectory.Names, 0, MEM_RELEASE))
                {
                    iRetVal = GetLastError();
                    printf("ERR: VirtualFree failed with %d\n", iRetVal);

                    goto shutdown;
                }
            }
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
        int iImportedFunctionCount = atoi(Options[1]);

        if (ePEType == PEType_x86)
        {
            MY_IMPORT_DIRECTORY MyImportDirectory = ParseImportDirectory(hFile, ePEType, MyNTOptionalHeader.OptionalHeader32.DataDirectory[1], iImportedFunctionCount, MySectionHeaders.SectionHeaders, MySectionHeaders.SectionHeadersCount);
            if (MyImportDirectory.iRetVal != 0)
            {
                goto shutdown;
            }

            PrintImportDirectory(MyImportDirectory);

            if (MyImportDirectory.sName != NULL)
            {
                if (!VirtualFree(MyImportDirectory.sName, 0, MEM_RELEASE))
                {
                    iRetVal = GetLastError();
                    printf("ERR: VirtualFree failed with %d\n", iRetVal);

                    goto shutdown;
                }
            }

            if (MyImportDirectory.ImportLookupTable != NULL)
            {
                if (!VirtualFree(MyImportDirectory.ImportLookupTable, 0, MEM_RELEASE))
                {
                    iRetVal = GetLastError();
                    printf("ERR: VirtualFree failed with %d\n", iRetVal);

                    goto shutdown;
                }
            }
        }
        else if (ePEType == PEType_x86_64)
        {
            MY_IMPORT_DIRECTORY MyImportDirectory = ParseImportDirectory(hFile, ePEType, MyNTOptionalHeader.OptionalHeader64.DataDirectory[1], iImportedFunctionCount, MySectionHeaders.SectionHeaders, MySectionHeaders.SectionHeadersCount);
            if (MyImportDirectory.iRetVal != 0)
            {
                goto shutdown;
            }

            PrintImportDirectory(MyImportDirectory);

            if (MyImportDirectory.sName != NULL)
            {
                if (!VirtualFree(MyImportDirectory.sName, 0, MEM_RELEASE))
                {
                    iRetVal = GetLastError();
                    printf("ERR: VirtualFree failed with %d\n", iRetVal);

                    goto shutdown;
                }
            }

            if (MyImportDirectory.ImportLookupTable != NULL)
            {
                if (!VirtualFree(MyImportDirectory.ImportLookupTable, 0, MEM_RELEASE))
                {
                    iRetVal = GetLastError();
                    printf("ERR: VirtualFree failed with %d\n", iRetVal);

                    goto shutdown;
                }
            }
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