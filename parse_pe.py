import os.path
import argparse
from enum import Enum

DOS_HEADER_SIZE = 64
NT_HEADER_SIGNATURE_SIZE = 4
NT_HEADER_FILE_HEADER_SIZE = 20

SECTION_HEADER_SIZE = 40

EXPORT_DIRECTORY_SIZE = 40
EXPORT_FUNCTION_RVA_SIZE = 4
EXPORT_ORDINAL_SIZE = 2
EXPORT_NAME_RVA_SIZE = 4

IMPORT_DIRECTORY_SIZE = 20
IMPORT_DIRECTORY_HINT_SIZE = 2

DATA_DIRS_SIZE = 120
SECTION_HEADER_SIZE = 40


def rva_to_offset(rva, section_hdrs):
    for section_hdr in section_hdrs:
        x = section_hdr.virtual_addr + section_hdr.raw_data_size

        if x >= rva:
            return rva - section_hdr.virtual_addr + section_hdr.raw_data_ptr

    return -1


def get_string_from_file(f=None) -> str:
    if f is None:
        return

    string_char = int.from_bytes(f.read(1), 'little')
    string_bytes = []

    while string_char != 0:
        string_bytes.append(string_char)
        string_char = int.from_bytes(f.read(1), 'little')

    return bytes(string_bytes).decode('utf-8')


class PEType(Enum):
    PE32 = 1
    PE64 = 2


class HintNameEntry:
    def __init__(self, hint=None, name=None):
        if hint is None and name is None:
            return

        self.hint = hint
        self.name = name


class DOSHeader:
    def __init__(self, dos_header_bytes: bytes = None) -> None:
        if dos_header_bytes is None:
            return

        self.e_magic = dos_header_bytes[0:2]
        self.e_cblp = int.from_bytes(dos_header_bytes[2:4], 'little')
        self.e_cp = int.from_bytes(dos_header_bytes[4:6], 'little')
        self.e_crlc = int.from_bytes(dos_header_bytes[6:8], 'little')
        self.e_cparhdr = int.from_bytes(
            dos_header_bytes[8:10], 'little')
        self.e_minalloc = int.from_bytes(
            dos_header_bytes[10:12], 'little')
        self.e_maxalloc = int.from_bytes(
            dos_header_bytes[12:14], 'little')
        self.e_ss = int.from_bytes(dos_header_bytes[14:16], 'little')
        self.e_sp = int.from_bytes(dos_header_bytes[16:18], 'little')
        self.e_csum = int.from_bytes(
            dos_header_bytes[18:20], 'little')
        self.e_ip = int.from_bytes(dos_header_bytes[20:22], 'little')
        self.e_cs = int.from_bytes(dos_header_bytes[22:24], 'little')
        self.e_lfarlc = int.from_bytes(
            dos_header_bytes[24:26], 'little')
        self.e_ovno = int.from_bytes(
            dos_header_bytes[26:28], 'little')
        self.e_res = int.from_bytes(dos_header_bytes[28:36])
        self.e_oemid = int.from_bytes(
            dos_header_bytes[36:38], 'little')
        self.e_oeminfo = int.from_bytes(
            dos_header_bytes[38:40], 'little')
        self.e_res2 = int.from_bytes(dos_header_bytes[40:60])
        self.e_lfanew = int.from_bytes(
            dos_header_bytes[60:64], 'little')

        self.len = len(dos_header_bytes)

    def __len__(self) -> int:
        return self.len

    def __repr__(self) -> str:
        return f'__repr__'

    def __str__(self) -> str:
        return f'\n\
                            DOS Header\n\
                Magic Number                : {self.e_magic}\n\
                Bytes on Last Page          : {hex(self.e_cblp)}\n\
                Pages in file               : {hex(self.e_cp)}\n\
                Relocations                 : {hex(self.e_crlc)}\n\
                Paragraph Header Size       : {hex(self.e_cparhdr)}\n\
                Min. extra paragraphs       : {hex(self.e_minalloc)}\n\
                Max. extra paragraphs       : {hex(self.e_maxalloc)}\n\
                Initial Relative SS Value   : {hex(self.e_ss)}\n\
                Initial SP Value            : {hex(self.e_sp)}\n\
                Checksum                    : {hex(self.e_csum)}\n\
                Initial IP Value            : {hex(self.e_ip)}\n\
                Initial Relative CS Value   : {hex(self.e_cs)}\n\
                File Addr of Reloc Table    : {hex(self.e_lfarlc)}\n\
                Overlay Number              : {hex(self.e_ovno)}\n\
                Reserved Words              : {hex(self.e_res)}\n\
                OEM Identifier              : {hex(self.e_oemid)}\n\
                OEM Information             : {hex(self.e_oeminfo)}\n\
                Reserved Words              : {hex(self.e_res2)}\n\
                File Addr New EXE Header    : {hex(self.e_lfanew)}\n'


class DOSStub:
    def __init__(self, dos_stub_bytes: bytes = None) -> None:
        if dos_stub_bytes is None:
            return

        self.stub = dos_stub_bytes
        self.len = len(self.stub)

    def __len__(self) -> int:
        return self.len

    def __str__(self) -> str:
        return f'\n\
            DOS Stub\n\
            {self.stub}\n'


class NTHeader:
    def __init__(self, nt_header_bytes: bytes = None) -> None:
        if nt_header_bytes is None:
            return

        self.signature = NTHeaderSignature()
        self.file_header = NTHeaderFileHeader()
        self.optional_header = NTHeaderOptionalHeader()

        self.len = len(nt_header_bytes)

    def __len__(self) -> int:
        return self.len

    def __str__(self) -> str:
        pass


class NTHeaderSignature():
    def __init__(self, nt_header_signature_bytes: bytes = None) -> None:
        if nt_header_signature_bytes is None:
            return

        self.signature = nt_header_signature_bytes
        self.len = len(nt_header_signature_bytes)

    def __len__(self) -> int:
        return self.len

    def __str__(self) -> str:
        return f'\n\
                NT Header Signature\n\
                    {self.signature}\n\
            '


class NTHeaderFileHeader:
    def __init__(self, file_header_bytes: bytes = None) -> None:
        if file_header_bytes is None:
            return

        self.machine = int.from_bytes(
            file_header_bytes[0:2], 'little')
        self.section_count = int.from_bytes(
            file_header_bytes[2:4], 'little')
        self.time_date_stamp = int.from_bytes(
            file_header_bytes[4:8], 'little')
        self.sym_tbl_ptr = int.from_bytes(
            file_header_bytes[8:12], 'little')
        self.symbol_count = int.from_bytes(
            file_header_bytes[12:16], 'little')
        self.optl_hdr_size = int.from_bytes(
            file_header_bytes[16:18], 'little')
        self.characteristics = int.from_bytes(
            file_header_bytes[18:20], 'little')

        self.len = len(file_header_bytes)

    def __len__(self) -> int:
        return self.len

    def __str__(self) -> str:
        return f'\n\
                            File Header\n\
                Machine                     : {hex(self.machine)}\n\
                Section Count               : {hex(self.section_count)}\n\
                Time Date Stamp             : {hex(self.time_date_stamp)}\n\
                Sym Table Ptr               : {hex(self.sym_tbl_ptr)}\n\
                Sym Count                   : {hex(self.symbol_count)}\n\
                Optional Hdr Size           : {hex(self.optl_hdr_size)}\n\
                Characteristics             : {hex(self.characteristics)}\n'


class DataDirectory:
    def __init__(self, va: int = None, size: int = None) -> None:
        if va is None or size is None:
            return

        self.va = va
        self.size = size

        self.len = 4 + 4

    def __len__(self) -> int:
        return self.len

    def __str__(self) -> str:
        return f''


class NTHeaderOptionalHeader:
    def __init__(self, optional_header_bytes: bytes = None) -> None:
        if optional_header_bytes is None:
            return
        else:
            self.base_of_data = -1

            self.magic = int.from_bytes(optional_header_bytes[0:2], 'little')
            self.mjr_lnkr_ver = optional_header_bytes[2]
            self.mnr_lnkr_ver = optional_header_bytes[3]
            self.code_size = int.from_bytes(
                optional_header_bytes[4:8], 'little')
            self.initialized_data_size = int.from_bytes(
                optional_header_bytes[8:12], 'little')
            self.uninitialized_data_size = int.from_bytes(
                optional_header_bytes[12:16], 'little')
            self.entry_point_addr = int.from_bytes(
                optional_header_bytes[16:20], 'little')
            self.base_of_code = int.from_bytes(
                optional_header_bytes[20:24], 'little')

            # 32 bit exes
            if self.magic == int.from_bytes(bytes([11, 1]), 'little'):
                self.base_of_data = int.from_bytes(
                    optional_header_bytes[24:28], 'little')
                self.base = int.from_bytes(
                    optional_header_bytes[28:32], 'little')
                self.section_alignment = int.from_bytes(
                    optional_header_bytes[32:36], 'little')
                self.file_alignment = int.from_bytes(
                    optional_header_bytes[36:40], 'little')
                self.mjr_os_ver = int.from_bytes(
                    optional_header_bytes[40:42], 'little')
                self.mnr_os_ver = int.from_bytes(
                    optional_header_bytes[42:44], 'little')
                self.mjr_img_ver = int.from_bytes(
                    optional_header_bytes[44:46], 'little')
                self.mnr_img_ver = int.from_bytes(
                    optional_header_bytes[46:48], 'little')
                self.mjr_subsys_ver = int.from_bytes(
                    optional_header_bytes[48:50], 'little')
                self.mnr_subsys_ver = int.from_bytes(
                    optional_header_bytes[50:52], 'little')
                self.win32_ver_val = int.from_bytes(
                    optional_header_bytes[52:56], 'little')
                self.size = int.from_bytes(
                    optional_header_bytes[56:60], 'little')
                self.hdrs_size = int.from_bytes(
                    optional_header_bytes[60:64], 'little')
                self.checksum = int.from_bytes(
                    optional_header_bytes[64:68], 'little')
                self.subsystem = int.from_bytes(
                    optional_header_bytes[68:70], 'little')
                self.dll_characteristics = int.from_bytes(
                    optional_header_bytes[70:72], 'little')
                self.stack_rsrv_size = int.from_bytes(
                    optional_header_bytes[72:76], 'little')
                self.stack_comm_size = int.from_bytes(
                    optional_header_bytes[76:80], 'little')
                self.heap_rsrv_size = int.from_bytes(
                    optional_header_bytes[80:84], 'little')
                self.heap_comm_size = int.from_bytes(
                    optional_header_bytes[84:88], 'little')
                self.loader_flags = int.from_bytes(
                    optional_header_bytes[88:92], 'little')
                self.rva_sizes_count = int.from_bytes(
                    optional_header_bytes[92:96], 'little')

                # TODO limit reading to rva_sizes_count
                # Data Directories
                self.export_directory = DataDirectory(int.from_bytes(optional_header_bytes[96:100], 'little'), int.from_bytes(
                    optional_header_bytes[100:104], 'little'))
                self.import_directory = DataDirectory(int.from_bytes(optional_header_bytes[104:108], 'little'), int.from_bytes(
                    optional_header_bytes[108:112], 'little'))
                self.resource_directory = DataDirectory(int.from_bytes(optional_header_bytes[112:116], 'little'), int.from_bytes(
                    optional_header_bytes[116:120], 'little'))
                self.exception_directory = DataDirectory(int.from_bytes(optional_header_bytes[120:124], 'little'), int.from_bytes(
                    optional_header_bytes[124:128], 'little'))
                self.certificate_directory = DataDirectory(int.from_bytes(optional_header_bytes[128:132], 'little'), int.from_bytes(
                    optional_header_bytes[132:136], 'little'))
                self.base_reloc_directory = DataDirectory(int.from_bytes(optional_header_bytes[136:140], 'little'), int.from_bytes(
                    optional_header_bytes[140:144], 'little'))
                self.debug_directory = DataDirectory(int.from_bytes(optional_header_bytes[144:148], 'little'), int.from_bytes(
                    optional_header_bytes[148:152], 'little'))
                self.architecture = DataDirectory(int.from_bytes(optional_header_bytes[152:156], 'little'), int.from_bytes(
                    optional_header_bytes[156:160], 'little'))
                self.global_ptr = DataDirectory(int.from_bytes(optional_header_bytes[160:164], 'little'), int.from_bytes(
                    optional_header_bytes[164:168], 'little'))
                self.tls_directory = DataDirectory(int.from_bytes(optional_header_bytes[168:172], 'little'), int.from_bytes(
                    optional_header_bytes[172:176], 'little'))
                self.load_config_directory = DataDirectory(int.from_bytes(optional_header_bytes[176:180], 'little'), int.from_bytes(
                    optional_header_bytes[180:184], 'little'))
                self.bound_import = DataDirectory(int.from_bytes(optional_header_bytes[184:188], 'little'), int.from_bytes(
                    optional_header_bytes[188:192], 'little'))
                self.iat = DataDirectory(int.from_bytes(optional_header_bytes[192:196], 'little'), int.from_bytes(
                    optional_header_bytes[196:200], 'little'))
                self.delay_import_descr = DataDirectory(int.from_bytes(optional_header_bytes[200:204], 'little'), int.from_bytes(
                    optional_header_bytes[204:208], 'little'))
                self.clr_header = DataDirectory(int.from_bytes(optional_header_bytes[208:212], 'little'), int.from_bytes(
                    optional_header_bytes[212:216], 'little'))
                self.reserved = DataDirectory(int.from_bytes(optional_header_bytes[216:220], 'little'), int.from_bytes(
                    optional_header_bytes[220:224], 'little'))

            # 64 bit exes will not have base_of_data_field
            elif self.magic == int.from_bytes(bytes([11, 2]), 'little'):
                self.base = int.from_bytes(
                    optional_header_bytes[24:32], 'little')
                self.section_alignment = int.from_bytes(
                    optional_header_bytes[32:36], 'little')
                self.file_alignment = int.from_bytes(
                    optional_header_bytes[36:40], 'little')
                self.mjr_os_ver = int.from_bytes(
                    optional_header_bytes[40:42], 'little')
                self.mnr_os_ver = int.from_bytes(
                    optional_header_bytes[42:44], 'little')
                self.mjr_img_ver = int.from_bytes(
                    optional_header_bytes[44:46], 'little')
                self.mnr_img_ver = int.from_bytes(
                    optional_header_bytes[46:48], 'little')
                self.mjr_subsys_ver = int.from_bytes(
                    optional_header_bytes[48:50], 'little')
                self.mnr_subsys_ver = int.from_bytes(
                    optional_header_bytes[50:52], 'little')
                self.win32_ver_val = int.from_bytes(
                    optional_header_bytes[52:56], 'little')
                self.size = int.from_bytes(
                    optional_header_bytes[56:60], 'little')
                self.hdrs_size = int.from_bytes(
                    optional_header_bytes[60:64], 'little')
                self.checksum = int.from_bytes(
                    optional_header_bytes[64:68], 'little')
                self.subsystem = int.from_bytes(
                    optional_header_bytes[68:70], 'little')
                self.dll_characteristics = int.from_bytes(
                    optional_header_bytes[70:72], 'little')
                self.stack_rsrv_size = int.from_bytes(
                    optional_header_bytes[72:80], 'little')
                self.stack_comm_size = int.from_bytes(
                    optional_header_bytes[80:88], 'little')
                self.heap_rsrv_size = int.from_bytes(
                    optional_header_bytes[88:96], 'little')
                self.heap_comm_size = int.from_bytes(
                    optional_header_bytes[96:104], 'little')
                self.loader_flags = int.from_bytes(
                    optional_header_bytes[104:108], 'little')
                self.rva_sizes_count = int.from_bytes(
                    optional_header_bytes[108:112], 'little')

                # TODO limit reading to rva_sizes_count
                # Data Directories
                self.export_directory = DataDirectory(int.from_bytes(optional_header_bytes[112:116], 'little'), int.from_bytes(
                    optional_header_bytes[116:120], 'little'))
                self.import_directory = DataDirectory(int.from_bytes(optional_header_bytes[120:124], 'little'), int.from_bytes(
                    optional_header_bytes[124:128], 'little'))
                self.resource_directory = DataDirectory(int.from_bytes(optional_header_bytes[128:132], 'little'), int.from_bytes(
                    optional_header_bytes[132:136], 'little'))
                self.exception_directory = DataDirectory(int.from_bytes(optional_header_bytes[136:140], 'little'), int.from_bytes(
                    optional_header_bytes[140:144], 'little'))
                self.certificate_directory = DataDirectory(int.from_bytes(optional_header_bytes[144:148], 'little'), int.from_bytes(
                    optional_header_bytes[148:152], 'little'))
                self.base_reloc_directory = DataDirectory(int.from_bytes(optional_header_bytes[152:156], 'little'), int.from_bytes(
                    optional_header_bytes[156:160], 'little'))
                self.debug_directory = DataDirectory(int.from_bytes(optional_header_bytes[160:164], 'little'), int.from_bytes(
                    optional_header_bytes[164:168], 'little'))
                self.architecture = DataDirectory(int.from_bytes(optional_header_bytes[168:172], 'little'), int.from_bytes(
                    optional_header_bytes[172:176], 'little'))
                self.global_ptr = DataDirectory(int.from_bytes(optional_header_bytes[176:180], 'little'), int.from_bytes(
                    optional_header_bytes[180:184], 'little'))
                self.tls_directory = DataDirectory(int.from_bytes(optional_header_bytes[184:188], 'little'), int.from_bytes(
                    optional_header_bytes[188:192], 'little'))
                self.load_config_directory = DataDirectory(int.from_bytes(optional_header_bytes[192:196], 'little'), int.from_bytes(
                    optional_header_bytes[196:200], 'little'))
                self.bound_import = DataDirectory(int.from_bytes(optional_header_bytes[200:204], 'little'), int.from_bytes(
                    optional_header_bytes[204:208], 'little'))
                self.iat = DataDirectory(int.from_bytes(optional_header_bytes[208:212], 'little'), int.from_bytes(
                    optional_header_bytes[212:216], 'little'))
                self.delay_import_descr = DataDirectory(int.from_bytes(optional_header_bytes[216:220], 'little'), int.from_bytes(
                    optional_header_bytes[220:224], 'little'))
                self.clr_header = DataDirectory(int.from_bytes(optional_header_bytes[224:228], 'little'), int.from_bytes(
                    optional_header_bytes[228:232], 'little'))
                self.reserved = DataDirectory(int.from_bytes(optional_header_bytes[232:236], 'little'), int.from_bytes(
                    optional_header_bytes[236:240], 'little'))

        self.len = len(optional_header_bytes)

    def __len__(self) -> int:
        return self.len

    def __str__(self) -> str:
        return f'\n\
                        Optional Header\n\
                Magic                       : {hex(self.magic)}\n\
                Major Linker Version        : {hex(self.mjr_lnkr_ver)}\n\
                Minor Linker Version        : {hex(self.mnr_lnkr_ver)}\n\
                Code Size                   : {hex(self.code_size)}\n\
                Initialized Data Size       : {hex(self.initialized_data_size)}\n\
                Uninitialized Data Size     : {hex(self.uninitialized_data_size)}\n\
                Entry Point Addr            : {hex(self.entry_point_addr)}\n\
                Base of Code                : {hex(self.base_of_code)}\n\
                Base of Data                : {hex(self.base_of_data) if self.base_of_data != -1 else -1}\n\
                Image Base                  : {hex(self.base)}\n\
                Section Alignment           : {hex(self.section_alignment)}\n\
                File Alignment              : {hex(self.file_alignment)}\n\
                Major OS Version            : {hex(self.mjr_os_ver)}\n\
                Minor OS Version            : {hex(self.mnr_os_ver)}\n\
                Major Image Version         : {hex(self.mjr_img_ver)}\n\
                Minor Image Version         : {hex(self.mnr_img_ver)}\n\
                Major Subsystem Version     : {hex(self.mjr_subsys_ver)}\n\
                Minor Subsystem Version     : {hex(self.mnr_subsys_ver)}\n\
                Win32 Version Value         : {hex(self.win32_ver_val)}\n\
                Size of Image               : {hex(self.size)}\n\
                Size of Headers             : {hex(self.hdrs_size)}\n\
                Checksum                    : {hex(self.checksum)}\n\
                Subsystem                   : {hex(self.subsystem)}\n\
                Dll Characteristics         : {hex(self.dll_characteristics)}\n\
                Stack Reserve Size          : {hex(self.stack_rsrv_size)}\n\
                Stack Commit Size           : {hex(self.stack_comm_size)}\n\
                Heap Reserve Size           : {hex(self.heap_rsrv_size)}\n\
                Heap Commit Size            : {hex(self.heap_comm_size)}\n\
                Loader Flags                : {hex(self.loader_flags)}\n\
                RVAs and Sizes Count        : {hex(self.rva_sizes_count)}\n\
                Export Directory            : RVA {hex(self.export_directory.va)}, Size {hex(self.export_directory.size)}\n\
                Import Directory            : RVA {hex(self.import_directory.va)}, Size {hex(self.import_directory.size)}\n\
                Resource Directory          : RVA {hex(self.resource_directory.va)}, Size {hex(self.resource_directory.size)}\n\
                Exception Directory         : RVA {hex(self.exception_directory.va)}, Size {hex(self.exception_directory.size)}\n\
                Certificate Directory       : RVA {hex(self.certificate_directory.va)}, Size {hex(self.certificate_directory.size)}\n\
                Base Reloc Directory        : RVA {hex(self.base_reloc_directory.va)}, Size {hex(self.base_reloc_directory.size)}\n\
                Debug Directory             : RVA {hex(self.debug_directory.va)}, Size {hex(self.debug_directory.size)}\n\
                Architecture                : RVA {hex(self.architecture.va)}, Size {hex(self.architecture.size)}\n\
                Global Pointer              : RVA {hex(self.global_ptr.va)}, Size {hex(self.global_ptr.size)}\n\
                TLS Directory               : RVA {hex(self.tls_directory.va)}, Size {hex(self.tls_directory.size)}\n\
                Load Config Directory       : RVA {hex(self.load_config_directory.va)}, Size {hex(self.load_config_directory.size)}\n\
                Bound Import                : RVA {hex(self.bound_import.va)}, Size {hex(self.bound_import.size)}\n\
                IAT                         : RVA {hex(self.iat.va)}, Size {hex(self.iat.size)}\n\
                Delay Import Descriptor     : RVA {hex(self.delay_import_descr.va)}, Size {hex(self.delay_import_descr.size)}\n\
                CLR Header                  : RVA {hex(self.clr_header.va)}, Size {hex(self.clr_header.size)}\n\
                Reserved                    : RVA {hex(self.reserved.va)}, Size {hex(self.reserved.size)}\n\
                '


class SectionHeader:
    def __init__(self, section_header_bytes: bytes = None) -> None:
        if section_header_bytes is None:
            return

        self.name = section_header_bytes[0:8].decode('utf-8')
        self.virtual_size = int.from_bytes(
            section_header_bytes[8:12], 'little')
        self.virtual_addr = int.from_bytes(
            section_header_bytes[12:16], 'little')
        self.raw_data_size = int.from_bytes(
            section_header_bytes[16:20], 'little')
        self.raw_data_ptr = int.from_bytes(
            section_header_bytes[20:24], 'little')
        self.reloc_ptr = int.from_bytes(section_header_bytes[24:28], 'little')
        self.line_nums_ptr = int.from_bytes(
            section_header_bytes[28:32], 'little')
        self.reloc_count = int.from_bytes(
            section_header_bytes[32:34], 'little')
        self.line_nums_count = int.from_bytes(
            section_header_bytes[34:36], 'little')
        self.characteristics = int.from_bytes(
            section_header_bytes[36:40], 'little')

        self.len = len(section_header_bytes)

    def __len__(self) -> int:
        return self.len

    def __str__(self) -> str:
        return f'\n\
                Name                        : {self.name}\n\
                Virtual Size                : {hex(self.virtual_size)}\n\
                Virtual Addr                : {hex(self.virtual_addr)}\n\
                Raw Data Size               : {hex(self.raw_data_size)}\n\
                Raw Data Pointer            : {hex(self.raw_data_ptr)}\n\
                Reloc Pointer               : {hex(self.reloc_ptr)}\n\
                Line Numbers Pointer        : {hex(self.line_nums_ptr)}\n\
                Relocs Count                : {hex(self.reloc_count)}\n\
                Line Numbers Count          : {hex(self.line_nums_count)}\n\
                Characteristics             : {hex(self.characteristics)}\n\
                '


class ExportDirectory:
    def __init__(self, export_directory_bytes: bytes = None, section_headers: list[SectionHeader] = None, f=None, export_directory_va_size: DataDirectory = None, print_function_count: int = 10) -> None:
        if export_directory_bytes is None or\
                section_headers is None or \
                f is None or\
                export_directory_va_size is None:
            return

        self.flags = int.from_bytes(export_directory_bytes[0:4], 'little')
        self.time_date_stamp = int.from_bytes(
            export_directory_bytes[4:8], 'little')
        self.major_ver = int.from_bytes(
            export_directory_bytes[8:10], 'little')
        self.minor_ver = int.from_bytes(
            export_directory_bytes[10:12], 'little')
        self.name_rva = int.from_bytes(
            export_directory_bytes[12:16], 'little')
        self.ordinal_base = int.from_bytes(
            export_directory_bytes[16:20], 'little')
        self.number_of_functions = int.from_bytes(
            export_directory_bytes[20:24], 'little')
        self.number_of_names = int.from_bytes(
            export_directory_bytes[24:28], 'little')
        self.address_of_functions = int.from_bytes(
            export_directory_bytes[28:32], 'little')
        self.address_of_names = int.from_bytes(
            export_directory_bytes[32:36], 'little')
        self.address_of_name_ordinals = int.from_bytes(
            export_directory_bytes[36:40], 'little')

        # We will create lists to store the features of the exported functions
        self.offsets = []
        self.function_rvas = []
        self.forwarders = []

        # Walk through the function rvas and check if the funtion definitions are part of the file or forwarded to another dll
        for idx in range(print_function_count):

            # Get the rva of the rva for the current iteration
            function_rva = self.address_of_functions + \
                (idx * EXPORT_FUNCTION_RVA_SIZE)
            
            # Get the offset for the rva in the file
            function_rva_offset = rva_to_offset(function_rva, section_headers)

            self.offsets.append(function_rva_offset)
            
            # Read the function rva from the file
            f.seek(function_rva_offset)
            self.function_rvas.append(int.from_bytes(
                f.read(EXPORT_FUNCTION_RVA_SIZE), 'little'))

            function_offset = rva_to_offset(
                self.function_rvas[idx], section_headers)

            # if the function offset is within the export directory then it points to a string of the form DLL.FunctionName
            # to which this function is forwarded
            if function_offset > rva_to_offset(export_directory_va_size.va, section_headers) and\
                    function_offset < rva_to_offset(export_directory_va_size.va + export_directory_va_size.size, section_headers):
                f.seek(function_offset)

                forwarder_name = get_string_from_file(f)
                self.forwarders.append(forwarder_name)
            else:
                # if the function offset is outside the export directory then it points to the function definition
                # append a dummy value to the fowarder list for display completeness
                self.forwarders.append('')

        self.ordinals = []

        for idx in range(print_function_count):
            name_ordinal_offset = rva_to_offset(
                self.address_of_name_ordinals + (idx * EXPORT_ORDINAL_SIZE), section_headers)

            f.seek(name_ordinal_offset)
            self.ordinals.append(self.ordinal_base +
                                 int.from_bytes(f.read(EXPORT_ORDINAL_SIZE), 'little'))

        self.name_rvas = []

        for idx in range(print_function_count):
            name_rva_offset = rva_to_offset(
                self.address_of_names + (idx * EXPORT_NAME_RVA_SIZE), section_headers)

            f.seek(name_rva_offset)
            self.name_rvas.append(int.from_bytes(
                f.read(EXPORT_NAME_RVA_SIZE), 'little'))

        self.names = []

        for idx in range(print_function_count):
            name_offset = rva_to_offset(self.name_rvas[idx], section_headers)
            f.seek(name_offset)

            name = get_string_from_file(f)

            self.names.append(name)

    def __str__(self) -> str:
        return_str = f'\n\
                        Export Directory\n\
                Flags                       : {hex(self.flags)}\n\
                Time Date Stamp             : {hex(self.time_date_stamp)}\n\
                Major Version               : {hex(self.major_ver)}\n\
                Minor Version               : {hex(self.minor_ver)}\n\
                Name RVA                    : {hex(self.name_rva)}\n\
                Ordinal Base                : {hex(self.ordinal_base)}\n\
                Addr Table Entries          : {hex(self.number_of_functions)}\n\
                Name Pointers Count         : {hex(self.number_of_names)}\n\
                Export Addr Table RVA       : {hex(self.address_of_functions)}\n\
                Name Pointer RVA            : {hex(self.address_of_names)}\n\
                Ordinal Table RVA           : {hex(self.address_of_name_ordinals)}\n\
           '

        return_str += '\n\n'
        return_str += f'  Offset        Ordinals        Function RVA        Name RVA            Name                                                Forwarder\n'

        for idx in range(len(self.function_rvas)):
            return_str += f' {hex(self.offsets[idx])}          {hex(self.ordinals[idx])}             {hex(self.function_rvas[idx])}           {hex(self.name_rvas[idx])}          {self.names[idx].ljust(25)}                        {self.forwarders[idx]}\n'

        return return_str


class ImportDirectory:
    def __init__(self, import_directory_bytes: bytes = None, f=None, section_headers: list[SectionHeader] = None, pe_type: PEType = None, print_function_count: int = 10) -> None:
        if import_directory_bytes is None and f is None and section_headers is None:
            return

        self.import_lookup_table_rva = int.from_bytes(
            import_directory_bytes[0:4], 'little')
        self.time_date_stamp = int.from_bytes(
            import_directory_bytes[4:8], 'little')
        self.forwarder_chain = int.from_bytes(
            import_directory_bytes[8:12], 'little')
        self.name_rva = int.from_bytes(import_directory_bytes[12:16], 'little')
        self.import_address_table_rva = int.from_bytes(
            import_directory_bytes[16:20], 'little')

        # Check if the object members are zero. This also signifies the end of the import directory list
        if self.is_zero():
            return

        name_offset = rva_to_offset(self.name_rva, section_headers)
        f.seek(name_offset)
        self.name = get_string_from_file(f)

        # Read imported functions
        self.import_lookup_table = []
        self.hint_name_table = []
        self.ordinals = []

        if pe_type == PEType.PE32:
            import_lookup_table_entry_size = 4
            ordinal_name_flag_mask = 0x80000000
        elif pe_type == PEType.PE64:
            import_lookup_table_entry_size = 8
            ordinal_name_flag_mask = 0x8000000000000000

        for idx in range(print_function_count):
            # Get the import lookup table RVA for the current iteration
            import_lookup_table_rva = self.import_lookup_table_rva + \
                (import_lookup_table_entry_size * idx)

            # Get the offset in the file for the above rva
            import_lookup_table_offset = rva_to_offset(
                import_lookup_table_rva, section_headers)

            # Get the import lookup table entry from the file
            f.seek(import_lookup_table_offset)
            import_lookup_table_entry = int.from_bytes(
                f.read(import_lookup_table_entry_size), 'little')

            # Check if the import lookup table entry is zero, which signifies the end of the table
            if import_lookup_table_entry != 0:
                # This entry can either be a hint-name value or a ordinal value
                # Bit no. 31/63 of the entry for 32/64 bit PE files is 1 if the entry is an ordinal and 0 if the entry is a hint name entry
                # This is checkd by masked the entry with the mask and checking the result
                ordinal_name_flag = import_lookup_table_entry & ordinal_name_flag_mask

                # This check is essentially to check if the bit no 31/63 is 0
                if ordinal_name_flag != ordinal_name_flag_mask:
                    # importing by name
                    # The hint name table entry rva is calculated as follows
                    hint_name_table_entry_rva = import_lookup_table_entry & 0x7fffffff
                    hint_name_table_entry_offset = rva_to_offset(
                        hint_name_table_entry_rva, section_headers)

                    if hint_name_table_entry_offset == -1:
                        continue

                    f.seek(hint_name_table_entry_offset)

                    # The first two bytes are the hint followed by the name of the function
                    hint = int.from_bytes(
                        f.read(IMPORT_DIRECTORY_HINT_SIZE), 'little')
                    name = get_string_from_file(f)

                    # Initialize a HintNameEntry object and append to the list
                    self.hint_name_table.append(HintNameEntry(hint, name))

                    # Add a dummy -ve value to the ordinal list for display completeness
                    self.ordinals.append(-1)

                # This check is essentially to check if the bit no 31/63 is 1
                elif ordinal_name_flag == ordinal_name_flag_mask:
                    # importing by ordinal
                    # Get the ordinal number as follows
                    ordinal_number = import_lookup_table_entry & 0xffff

                    # Add a dummy -ve value to the hint name table for display completeness
                    self.hint_name_table.append(HintNameEntry(-1, ''))
                    self.ordinals.append(ordinal_number)

                self.import_lookup_table.append(import_lookup_table_entry)

            # Reached the end of the import lookup table
            elif import_lookup_table_entry == 0:
                return

    def is_zero(self) -> bool:
        return self.import_lookup_table_rva == 0 and \
            self.time_date_stamp == 0 and\
            self.forwarder_chain == 0 and\
            self.name_rva == 0 and\
            self.import_address_table_rva == 0

    def __str__(self) -> str:
        return_str = f'\n\
            Import Directory - {self.name}\n\
                Import Lookup Table RVA     : {hex(self.import_lookup_table_rva)}\n\
                Time\Date Stamp             : {hex(self.time_date_stamp)}\n\
                Forwarder Chain             : {hex(self.forwarder_chain)}\n\
                Name RVA                    : {hex(self.name_rva)}\n\
                Import Addr Table RVA       : {hex(self.import_address_table_rva)}\n\
                        \n\
                        Imported Functions\n\
Ordinal     Hint      Name                                Original Thunk\
    '
        for idx in range(len(self.hint_name_table)):
            return_str += f'\n\
{str(hex(self.ordinals[idx]).ljust(7))}     {str(hex(self.hint_name_table[idx].hint)).ljust(1)}      {self.hint_name_table[idx].name.ljust(30)}         {hex(self.import_lookup_table[idx])}\
        '

        return return_str


def main(args):
    if not args.dos_header and \
            not args.dos_stub and \
        not args.nt_headers and \
            not args.nt_headers_signature and \
            not args.nt_headers_file_header and \
            not args.nt_headers_optional_header and \
            not args.section_headers and \
            args.exported_functions is None and \
            args.imported_functions is None:
        print('Nothing to print. Exiting... Pass -h flag for help')
        return

    if not os.path.exists(args.filename):
        print(f'ERR: Input file {args.filename} not found')
        return

    with open(args.filename, 'rb') as f:
        # DOS Header is the first block of data in the file
        dos_header = DOSHeader(f.read(DOS_HEADER_SIZE))

        if args.dos_header:
            print(dos_header)

        # DOS Stub follows the DOS Header
        dos_stub = DOSStub(
            f.read(dos_header.e_lfanew - DOS_HEADER_SIZE))

        if args.dos_stub:
            print(dos_stub)

        # NT headers follow the DOS Stub
        nt_header_signature = NTHeaderSignature(
            f.read(NT_HEADER_SIGNATURE_SIZE))

        if args.nt_headers_signature:
            print(nt_header_signature)

        nt_headers_file_header = NTHeaderFileHeader(
            f.read(NT_HEADER_FILE_HEADER_SIZE))

        if args.nt_headers_file_header:
            print(nt_headers_file_header)

        nt_headers_optional_header = NTHeaderOptionalHeader(
            f.read(nt_headers_file_header.optl_hdr_size))

        if args.nt_headers_optional_header:
            print(nt_headers_optional_header)

        section_headers = []

        # Section Headers follow the NT headers
        for _ in range(nt_headers_file_header.section_count):
            section_headers.append(
                SectionHeader(f.read(SECTION_HEADER_SIZE)))

        if args.section_headers:
            print('\n                         Section Headers')
            for section_header in section_headers:
                print(section_header)

        # Exported Functions

        # Check if the --exported-functions flags is passed on the command line
        if args.exported_functions is not None:

            # Get the offset of the export directory in the file
            export_directiory_offset = rva_to_offset(
                nt_headers_optional_header.export_directory.va, section_headers)

            if export_directiory_offset == -1:
                return

            # Initialize a ExportDirectory object by passing the bytes read from the file to the class 'constructor'
            f.seek(export_directiory_offset)
            export_directory = ExportDirectory(
                f.read(EXPORT_DIRECTORY_SIZE), section_headers, f, nt_headers_optional_header.export_directory, int(args.exported_functions))

            print(export_directory)

        # Store the bitness of the PE File. This is required since the Import Lookup Table has 32 bit entries for 32 bit PE files and 64 bit entries for 64 bit PE files
        if nt_headers_file_header.machine == 0x8664:
            pe_type = PEType.PE64
        elif nt_headers_file_header.machine == 0x14c:
            pe_type = PEType.PE32

        # Imported Functions
        # List to hold the import directories.
        import_directories = []

        # Check if the --imported-functions flags is passed on the command line
        if args.imported_functions is not None:

            # Get the offset of the import directory in the file
            first_import_directory_offset = rva_to_offset(
                nt_headers_optional_header.import_directory.va, section_headers)

            if first_import_directory_offset == -1:
                return

            # Initialize a ImportDirectory object by passing the bytes read from the file to class 'constructor'
            f.seek(first_import_directory_offset)
            import_directory = ImportDirectory(
                f.read(IMPORT_DIRECTORY_SIZE), f, section_headers, pe_type, int(args.imported_functions))

            # The import directory entry is zero to signify the end of the array, so we check if all the object members are zero
            # if not zero continue walking the list
            while not import_directory.is_zero():
                import_directories.append(import_directory)

                f.seek(first_import_directory_offset +
                       (len(import_directories) * IMPORT_DIRECTORY_SIZE))

                # Initialize a ImportDirectory object by passing the bytes read from the file to class 'constructor'
                import_directory = ImportDirectory(
                    f.read(IMPORT_DIRECTORY_SIZE), f, section_headers, pe_type, int(args.imported_functions))

            for import_directory in import_directories:
                print(import_directory)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        prog='python parse_pe.py', description='Print the information contained in the PE file.')

    parser.add_argument('filename')

    parser.add_argument('--dos-header', action='store_true',
                        help='Print the DOS header')
    parser.add_argument('--dos-stub', action='store_true',
                        help='Print the DOS stub')
    parser.add_argument('--nt-headers', action='store_true',
                        help='Print the NT headers')
    parser.add_argument('--nt-headers-signature',
                        action='store_true', help='Print the NT headers Signature')
    parser.add_argument('--nt-headers-file-header',
                        action='store_true', help='Print the NT headers File header')
    parser.add_argument('--nt-headers-optional-header',
                        action='store_true', help='Print the NT headers Optional header')
    parser.add_argument('--section-headers', action='store_true',
                        help='Print the section headers')
    parser.add_argument('--exported-functions',
                        help='Print the exported functions. Count limited to EXPORTED_FUNCTIONS. Negative values of Hint and Ordinal means that value is NULL')
    parser.add_argument('--imported-functions',
                        help='Print the imported functions. Count limited to IMPORTED_FUNCTIONS. Negative values of Hint and Ordinal means that value is NULL')
    args = parser.parse_args()

    main(args)
