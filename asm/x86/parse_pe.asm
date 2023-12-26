section .text
global _parse_pe

%include 'utils_inc_text_32.asm'

extern _PathFileExistsA@4
extern _OpenFile@12
extern _ReadFile@20
extern _GetLastError@0
extern _CloseHandle@4


; arg0: return addr for optional header     [ebp + 8]
; arg1: optional header size                [ebp + 12]
; arg1: file handle                         [ebp + 16]
; arg2: file type 1: 64 bit 0: 32 bit       [ebp + 20]
;
; return: addr for optional header          eax
;
parse_nt_header_optional_header:
    push ebp
    mov ebp, esp

    push dword 0
    push dword 0
    push dword [ebp + 12]               ; bytes to read, actual size
    push dword [ebp + 8]
    push dword [ebp + 16]
    call _ReadFile@20

    cmp eax, 1                          ; 1: successful read
    je .continue
        push ret_val_8_nt_header_optional_header_str.len
        push ret_val_8_nt_header_optional_header_str
        call print_string

        call _GetLastError@0

        jmp .shutdown

.continue:

.shutdown:
    mov eax, [ebp + 8]              ; return addr in eax

    add esp, 16                     ; free arg stack

    leave
    ret

; arg0: return addr of file header      [ebp + 8]
; arg1: file handle                     [ebp + 12]
;
; return: addr of file header           eax
parse_nt_header_file_header:
    push ebp
    mov ebp, esp

    push dword 0
    push dword 0
    push 20                         ; bytes to read, actual size
    push dword [ebp + 8]
    push dword [ebp + 12]
    call _ReadFile@20

    cmp eax, 1                      ; 1: successful read
    je .continue
        push ret_val_7_nt_header_file_header_str.len
        push ret_val_7_nt_header_file_header_str
        call print_string

        call _GetLastError@0

        jmp .shutdown

.continue:

.shutdown:
    mov eax, [ebp + 8]          ; return addr in eax

    add esp, 8                  ; free arg stack

    leave
    ret

; arg1: file handle                     [ebp + 12]
;
; return: addr of file header           eax
parse_nt_header_signature:
    push ebp
    mov ebp, esp

    ; [ebp - 4] = signature
    sub esp, 4                      ; allocate local variable space

    push dword 0
    push dword 0
    push 4                          ; number of bytes to read
    mov eax, ebp
    sub eax, 4
    push eax                        ; output buffer
    push dword [ebp + 8]            ; file handle
    call _ReadFile@20

    cmp eax, 1                      ; 1: successful read
    je .continue
        push ret_val_6_nt_header_signature_str.len
        push ret_val_6_nt_header_signature_str
        call print_string

        call _GetLastError@0

        jmp .shutdown

.continue:
    ; push dword 4
    ; mov eax, ebp
    ; sub eax, 4
    ; push eax
    ; call print_string

.shutdown:
    add esp, 4                  ; free local variable space

    add esp, 4                  ; free arg stack

    leave
    ret

; arg0: sub size                [ebp + 8]
; arg1: file handle             [ebp + 12]
parse_dos_stub:
    push ebp
    mov ebp, esp

    ; [ebp - 256] = dos stub
    sub esp, 256                    ; allocate local variable space

    push dword 0
    push dword 0
    push dword [ebp + 8]            ; number of bytes to read
    mov eax, ebp
    sub eax, 256               
    push dword eax                  ; output buffer
    push dword [ebp + 12]           ; file handle
    call _ReadFile@20

    cmp eax, 1                      ; 1: successful read
    je .continue
        push ret_val_5_dos_stub_str.len
        push ret_val_5_dos_stub_str
        call print_string

        call _GetLastError@0

        jmp .shutdown

.continue:
    ; push dword [ebp + 8]
    ; mov eax, ebp
    ; sub eax, 256
    ; push eax
    ; call print_string

.shutdown:
    add esp, 256                    ; free local variable space

    add esp, 8                      ; free arg stack

    leave
    ret

; arg0: return struct addr          [ebp + 8]
; arg1: file handle                 [ebp + 12]
;
; return: return struct addr        eax
parse_dos_header:
    push ebp
    mov ebp, esp

    push dword 0
    push dword 0
    push dword 64
    push dword [ebp + 8]
    push dword [ebp + 12]

    call _ReadFile@20

    cmp eax, 1                      ; if ReadFile is successful
    je .continue

        call _GetLastError@0

        mov [ebp - 4], eax          ; GetLastError in [ebp - 4]

        push ret_val_4_dos_header_str.len
        push ret_val_4_dos_header_str
        call print_string

        add esp, 8                  ; free arg stack

        leave
        ret

.continue:
    mov eax, [ebp + 8]              ; return struct addr to eax
    add esp, 8                      ; free arg stack

    leave
    ret

; arg0: ptr to file path            [ebp + 8]
; arg1: ptr to options              [ebp + 12]
parse_pe:
    push ebp
    mov ebp, esp

    ; [ebp - 144]                       = OpenFileStruct, [ebp - 4] = File Handle
    ; [ebp - 144 - 64]                  = return mem for my_dos_header
    ; [ebp - 144 - 64 - 20]             = return mem for file header
    ; [ebp - 144 - 64 - 20 - 256]       = return mem for optional header
    sub esp, OF_FILE_STRUCT_SIZE + DOS_HEADER_BUFFER_SIZE + NT_FILE_HEADER_BUFFER_SIZE + OPTIONAL_HEADER_BUFFER_SIZE              ; allocate local variable space

    push OF_READ
    mov edx, ebp
    sub edx, OF_FILE_STRUCT_SIZE
    push edx
    push dword [ebp + 8]
    call _OpenFile@12

    cmp eax, INVALID_HANDLE_VALUE
    jne .continue_open_file

    push ret_val_3_str.len
    push ret_val_3_str
    call print_string

    mov dword eax, 3

    jmp .shutdown
.continue_open_file:
    mov [ebp - 4], eax                  ; file Handle in [ebp - 4]

    push dword [ebp - 4]                ; file handle as arg
    mov ebx, ebp
    sub ebx, (OPTIONAL_HEADER_BUFFER_SIZE + DOS_HEADER_BUFFER_SIZE)
    push dword ebx                      ; my_dos_header addr as arg
    call parse_dos_header

    push dword [ebp - 4]                ; file handle as arg
    add eax, 0x3c
    xor ecx, ecx
    mov ecx, [eax]                      ; e_lfanew in ecx
    sub cx, DOS_HEADER_BUFFER_SIZE
    push ecx
    call parse_dos_stub

    push dword [ebp - 4]                ; file handle as arg
    call parse_nt_header_signature

    push dword [ebp - 4]                ; file handle as arg
    mov ebx, ebp
    sub ebx, OF_FILE_STRUCT_SIZE + DOS_HEADER_BUFFER_SIZE + NT_FILE_HEADER_BUFFER_SIZE
    push dword ebx                      ; file header addr as arg
    call parse_nt_header_file_header

    cmp word [eax], 0x8664
    je .64bit
        push dword 0
        jmp .continue_bitness_check
    .64bit:
        push dword 1

.continue_bitness_check:
    push dword [ebp - 4]
    xor ebx, ebx
    mov bx, [eax + 16]
    push ebx

    mov ebx, ebp
    sub ebx, OF_FILE_STRUCT_SIZE + DOS_HEADER_BUFFER_SIZE + NT_FILE_HEADER_BUFFER_SIZE + OPTIONAL_HEADER_BUFFER_SIZE
    push dword ebx                      ; optional header addr as arg

    call parse_nt_header_optional_header

.shutdown:
    push dword [ebp - 4]                ; file handle as arg
    call _CloseHandle@4

    add esp, OF_FILE_STRUCT_SIZE + DOS_HEADER_BUFFER_SIZE + NT_FILE_HEADER_BUFFER_SIZE + OPTIONAL_HEADER_BUFFER_SIZE              ; free local variable space

    add esp, 8                          ; free arg stack

    leave
    ret


; arg0: argc        [ebp + 8]
; arg1: *argv[]     [ebp + 12]
_parse_pe:
    push ebp
    mov ebp, esp

    cmp byte [ebp + 8], 3               ; argc == 3 ?

    je .continue1
        push ret_val_1_str.len
        push ret_val_1_str
        call print_string
        add esp, 8                      ; free print_string arg stack

        mov eax, 1
        
        add esp, 8                      ; free arg stack

        leave
        ret

    .continue1:
        xor edx, edx
        mov edx, [ebp + 12]             ; argv in edx
        mov edx, [edx + 4]              ; argv[1] in edx

        push edx
        call _PathFileExistsA@4

        cmp eax, 1                      ; does file exist ?
        je .continue2
        push ret_val_2_str.len
        push ret_val_2_str
        call print_string

        mov eax, 2

        add esp, 8                      ; free arg stack

        leave
        ret

    .continue2:

        xor edx, edx
        mov edx, [ebp + 12]             ; argv in edx

        add edx, 8                      ; command line Options in edx
        mov edx, [edx]
        push edx

        mov edx, [ebp + 12]             ; argv in edx
        add edx, 4                      ; command line FileName in edx
        mov edx, [edx]
        push edx

        call parse_pe

        xor eax, eax

        add esp, 8                      ; free arg stack

        leave
        ret


section .data
%include 'utils_inc_data_32.asm'

ret_val_1_str: db 'Usage: parse_pe.exe <filename> <options>', 0
.len equ $ - ret_val_1_str

ret_val_2_str: db 'ERR: Input file not exist', 0
.len equ $ - ret_val_2_str

ret_val_3_str: db 'Could not open file for reading', 0
.len equ $ - ret_val_3_str

ret_val_4_dos_header_str: db 'ERR: ReadFile failed, DOS Header', 0
.len equ $ - ret_val_4_dos_header_str

ret_val_5_dos_stub_str: db 'ERR: ReadFile failed, DOS stub', 0
.len equ $ - ret_val_5_dos_stub_str

ret_val_6_nt_header_signature_str: db 'ERR: ReadFile failed, NT Signature', 0
.len equ $ - ret_val_6_nt_header_signature_str

ret_val_7_nt_header_file_header_str: db 'ERR: ReadFile failed, NT File Header', 0
.len equ $ - ret_val_7_nt_header_file_header_str

ret_val_8_nt_header_optional_header_str: db 'ERR: ReadFile failed, NT Optional Header', 0
.len equ $ - ret_val_8_nt_header_optional_header_str

dos_header_arg: db '--dos-header', 0
.len equ $ - dos_header_arg

dos_stub_arg: db '--dos-stub', 0
.len equ $ - dos_stub_arg

nt_headers_arg: db '--nt-headers', 0
.len equ $ - nt_headers_arg

section_headers_arg: db '--section-headers', 0
.len equ $ - section_headers_arg

import_address_table_arg: db '--import-address-table', 0
.len equ $ - import_address_table_arg

export_address_table_arg: db '--export-address-table', 0
.len equ $ - export_address_table_arg

OF_READ equ 0
OF_FILE_STRUCT_SIZE equ 144
DOS_HEADER_BUFFER_SIZE equ 64
NT_FILE_HEADER_BUFFER_SIZE equ 32   ; 20 + 12 bytes padding to make it divisible by 16
OPTIONAL_HEADER_BUFFER_SIZE equ 256 ; 224 bytes / 240 bytes is required for 32 bit / 64 bit, padding bytes to make it divisible by 16
SECTION_HEADERS_BUFFER_SIZE equ 1000    ; 40 bytes per section header, 1000 will hold 25 sections
