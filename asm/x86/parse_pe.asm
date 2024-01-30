section .text
global _parse_pe

%include '../utils/utils_32_text.asm'

; arg0: rva                         [ebp + 8]
; arg1: section headers             [ebp + 12]
; arg2: section header count        [ebp + 16]
;
; returns offset                    rax > 0
rva_to_offset:
    push ebp
    mov ebp, esp

    ; [ebp - 4] = return code
    ; [ebp - 8] = current section header
    sub esp, 8                      ; allocate local variable space

    mov dword [ebp - 4], 0          ; return code

    mov ecx, [ebp + 16]             ; section header count
    mov edx, [ebp + 12]             ; section headers

    .loop:
        mov [ebp - 8], edx          ; current section header
        add edx, 12                 ; virtual addr
        mov eax, [edx]              ; virtual addr in eax

        add edx, 4                  ; size of raw data
        add eax, [edx]              ; eax = virtual addr + raw data size

        cmp eax, [ebp + 8]          ; x >= rva
        jge .return_offset

        add edx, 24                 ; add offset to end of section header (go to next header)

        dec ecx
        cmp ecx, 0
        jnz .loop

    .return_offset:
        mov eax, [ebp + 8]          ; rva in eax
        mov edx, [ebp - 8]          ; current section header

        add edx, 12                 ; virtual addr
        sub eax, [edx]              ; rva - virtual addr

        add edx, 8                  ; raw data ptr
        add eax, [edx]              ; rva - virtual addr + raw data pointer

        mov [ebp - 4], eax          ; return value
    
.shutdown:
    mov eax, [ebp - 4]              ; return value

    leave
    ret 12

; arg0: section headers             [ebp + 8]
; arg1: section header count        [ebp + 12]
loop_section_headers:
    push ebp
    mov ebp, esp

    ; ebp - 4 = return value
    sub esp, 4                      ; allocate local variable space

    mov dword [ebp - 4], 0          ; return value


    mov ecx, [ebp + 12]             ; section header count
    mov edx, [ebp + 8]              ; section headers

    .loop:
        add edx, 40                 ; add section header size (next section header)

        dec ecx
        cmp ecx, 0
        jnz .loop

.shutdown:
    mov eax, [ebp - 4]              ; return value

    leave
    ret 8

; arg0: import descriptor table rva     [ebp + 8]
; arg1: section headers                 [ebp + 12]
; arg2: section header count            [ebp + 16]
; arg3: base addr file contents         [ebp + 20]
loop_import_descriptor_table:
    push ebp
    mov ebp, esp

    ; ebp - 4 = return value
    ; ebp - 8 = offset
    sub esp, 8                      ; allocate local variable space

    mov dword [ebp - 4], 0          ; return value

    push dword [ebp + 16]           ; section header count
    push dword [ebp + 12]           ; section headers
    push dword [ebp + 8]            ; IDT rva
    call rva_to_offset              ; offset in eax

    cmp eax, 0                      ; offset == 0 ?
    jle .shutdown

    mov [ebp - 8], eax              ; offset
    mov eax, [ebp + 20]             ; base addr
    add eax, [ebp - 8]              ; base addr + offset
        
    .loop:
        add eax, 12                 ; name RVA
        cmp dword [eax], 0
        je .loop_end

        add eax, 8                  ; next IDT
        jmp .loop

    ; TODO: Loop through functions of each imported DLL

.loop_end:

.shutdown:
    mov eax, [ebp - 4]              ; return value

    leave
    ret 16

; arg0: export directory table rva      [ebp + 8]
; arg1: section headers                 [ebp + 12]
; arg2: section header count            [ebp + 16]
; arg3: file contents base addr         [ebp + 20]
loop_export_descriptor_table:
    push ebp
    mov ebp, esp

    ; ebp - 4 = return value
    ; ebp - 8 = offset
    sub esp, 8                      ; allocate local variable space

    mov dword [ebp - 4], 0          ; return value

    push dword [ebp + 16]           ; section header count
    push dword [ebp + 12]           ; section headers
    push dword [ebp + 8]            ; IDT rva
    call rva_to_offset              ; offset in eax

    cmp eax, 0                      ; offset == 0 ?
    jle .shutdown

    mov [ebp - 8], eax              ; offset
    mov eax, [ebp + 20]             ; base addr
    add eax, [ebp - 8]              ; base + offset

    mov ecx, [eax + 20]             ; number of entries in eat
    
    ; TODO: Loop through exported functions / names

.shutdown:
    mov eax, [ebp - 4]              ; return value

    leave
    ret 16

; arg0: base addr file contents      [ebp + 8]
; arg1: Options                      [ebp + 12]
parse_pe:
    push ebp
    mov ebp, esp

    ; ebp - 4 = return value
    ; ebp - 8 = nt header
    ; ebp - 12 = file header
    ; ebp - 16 = optional header
    ; ebp - 20 = section header count
    ; ebp - 24 = section headers
    ; ebp - 28 = file bitness 1: 64 bit, 0: 32 bit
    sub esp, 28                     ; allocate local variable space

    mov dword [ebp - 4], 0          ; return value

    ; retrive and  save the information to the above stack variables
    mov ebx, [ebp + 8]              ; base addr
    add ebx, 0x3c                   ; offset of e_lfanew
    movzx eax, word [ebx]           ; e_lfanew

    mov ebx, [ebp + 8]
    add ebx, eax                    ; nt headers
    mov [ebp - 8], ebx              ; nt headers saved

    add ebx, 4                      ; file header
    mov [ebp - 12], ebx             ; file header saved

    add ebx, 2                      ; section header count 
    movzx eax, word [ebx]
    mov [ebp - 20], eax             ; section header count saved

    add ebx, 18                     ; optional header
    mov [ebp - 16], ebx             ; optional header saved
    
    mov eax, [ebp - 12]             ; file header
    mov ax, [eax]
    cmp word ax, 0x14c              ; is file 32 bit
    je .32bit
        mov eax, [ebp - 16]         ; optional header
        add eax, 240                ; end of optional header, start of section headers

        mov [ebp - 24], eax         ; section headers
        mov dword [ebp - 28], 1     ; file bitness 1 for 64 bit

        jmp .continue_32_bit

    .32bit:
        mov eax, [ebp - 16]         ; optional header
        add eax, 224                ; end of optional header, start of section header

        mov [ebp - 24], eax         ; section headers
        mov dword [ebp - 24], 0     ; file bitness 0 for 32 bit

.continue_32_bit:
    ; loop section headers

    push dword [ebp - 20]           ; section header count
    push dword [ebp - 24]           ; section headers
    call loop_section_headers

.idt:
    ; loop IDT
    mov eax, [ebp - 16]             ; optional header

    cmp dword [ebp - 28], 0         ; is file 32 bit
    je .32bitidt
        add eax, 120                ; IDT
        mov eax, [eax]

        cmp eax, 0                  ; if IDT rva == 0 ?

        je .edt
        jmp .continue_bitcheck_idt

    .32bitidt:
        add eax, 104                ; IDT
        mov eax, [eax]

        cmp eax, 0                  ; if IDT rva == 0 ?

        je .edt

.continue_bitcheck_idt:
    push dword [ebp + 8]                ; base addr
    push dword [ebp - 20]               ; section header count
    push dword [ebp - 24]               ; section headers
    push eax                            ; IDT rva
    call loop_import_descriptor_table

.edt:
    ; loop EDT
    mov eax, [ebp - 16]             ; optional header

    cmp dword [ebp - 28], 0         ; is file 32 bit
    je .32bitedt
        add eax, 112                ; EDT
        mov eax, [eax]

        cmp eax, 0                  ; if EDT rva == 0 ?

        je .shutdown
        jmp .continue_bitcheck_edt

    .32bitedt:
        add eax, 96                 ; EDT
        mov eax, [eax]

        cmp eax, 0                  ; if EDT rva == 0 ?

        je .shutdown

.continue_bitcheck_edt:
    push dword [ebp + 8]                ; base addr
    push dword [ebp - 20]               ; section header count
    push dword [ebp - 24]               ; section headers
    push eax                            ; EDT rva
    call loop_export_descriptor_table

.shutdown:

    mov eax, [ebp - 4]                  ; return value

    leave
    ret 8

; arg0: argc        [ebp + 8]
; arg1: *argv[]     [ebp + 12]
_parse_pe:
    push ebp
    mov ebp, esp

    ; ebp - 4 = retuen value
    ; ebp - 148 = OFFILESTRUCT
    ; ebp - 152 = file handle
    ; ebp - 156 = getfilesize high order dw of file size
    ; ebp - 160 = getfilesize low order dw of file size
    ; ebp - 164 = allocated mem for input file read
    ; ebp - 168 = kernel handle
    ; ebp - 172 = std handle
    ; ebp - 176 = shlwapi addr
    sub esp, 176                            ; allocate local variable space

    mov dword [ebp - 4], 0                  ; return value

    call get_kernel_module_handle
    mov [ebp - 168], eax                    ; kernel handle

    push dword [ebp - 168]                  ; kernel handle
    call populate_kernel_function_ptrs_by_name

    push STD_HANDLE_ENUM
    call [get_std_handle]

    mov [ebp - 172], eax                    ; std handle

    cmp byte [ebp + 8], 3                   ; argc == 3 ?
    je .continue_argc_check
        push ret_val_1_str.len
        push ret_val_1_str
        push dword [ebp - 172]              ; std handle
        call print_string

        call [get_last_error]

        mov dword [ebp - 4], 1

        jmp .shutdown

.continue_argc_check:

    push xor_key.len
    push xor_key
    push shlwapi_xor.len
    push shlwapi_xor
    call my_xor

    push shlwapi_xor
    call [load_library_a]

    cmp eax, 0
    je .shutdown

    mov [ebp - 176], eax                    ; shlwapi addr

    push xor_key.len
    push xor_key
    push path_file_exists_a_xor.len
    push path_file_exists_a_xor
    call my_xor

    push path_file_exists_a_xor
    push dword [ebp - 176]                  ; shlwapi addr
    call get_proc_address_by_get_proc_addr

    cmp eax, 0
    je .shutdown

    mov [path_file_exists_a], eax

    mov edx, [ebp + 12]                     ; argv in edx
    mov edx, [edx + 4]                      ; argv[1] in edx

    push edx
    call [path_file_exists_a]

    cmp eax, 1                              ; does file exist
    je .continue_path_file_check
        push ret_val_2_str.len
        push ret_val_2_str
        push dword [ebp - 172]              ; std handle
        call print_string

        call [get_last_error]

        mov dword [ebp - 4], 2

        jmp .shutdown

.continue_path_file_check:
    push 0

    mov edx, esp
    sub edx, 148
    push edx

    mov edx, [ebp + 12]                             ; argv
    add edx, 4                                      ; argv + 1
    push dword [edx]                                ; argv[1]

    call [open_file]                                ; file handle in eax

    cmp eax, INVALID_HANDLE_VALUE
    jne .continue_open_file
        push ret_val_3_open_file_str.len
        push ret_val_3_open_file_str
        push dword [ebp - 172]              ; std handle
        call print_string

        call [get_last_error]

        mov dword [ebp - 4], 3

        jmp .shutdown

.continue_open_file:
    mov [ebp - 152], eax        ; file handle

    mov edx, ebp
    sub edx, 156
    push edx

    push dword [ebp - 152]
    call [get_file_size]                             ; file size in eax

    cmp eax, INVALID_FILE_SIZE
    jne .continue_get_file_size
        push ret_val_4_get_file_size_str.len
        push ret_val_4_get_file_size_str
        push dword [ebp - 172]              ; std handle
        call print_string

        call [get_last_error]

        mov dword [ebp - 4], 4

        jmp .shutdown

.continue_get_file_size:
    mov [ebp - 160], eax       ; file size saved

    mov edx, PAGE_READWRITE
    push edx

    mov edx, MEM_RESERVE
    or edx, MEM_COMMIT
    push edx

    push dword [ebp - 160]     ; file size
    push 0
    call [virtual_alloc]

    cmp eax, 0                                      ; if addr is 0
    jne .continue_virtual_alloc
        push ret_val_5_virtual_alloc_str.len
        push ret_val_5_virtual_alloc_str
        push dword [ebp - 172]              ; std handle
        call print_string
        
        call [get_last_error]

        mov dword [ebp - 4], 5

        jmp .shutdown

.continue_virtual_alloc:
    mov dword [ebp - 164], eax ; alloced mem saved

    push 0
    push 0
    push dword [ebp - 160]     ; file size
    push dword [ebp - 164]     ; alloced mem
    push dword [ebp - 152]     ; file handle
    call [read_file]

    cmp eax, 0                                      ; 1: successful read
    jne .continue_read_file
        push ret_val_6_read_file_str.len
        push ret_val_6_read_file_str
        push dword [ebp - 172]              ; std handle
        call print_string

        call [get_last_error]

        mov dword [ebp - 4], 6

        jmp .shutdown

.continue_read_file:
    mov edx, [ebp + 12]                             ; argv
    add edx, 8                                      ; command line Options
    push edx
    push dword [ebp - 164]     ; alloced mem
    call parse_pe

.shutdown:
    push MEM_RELEASE
    push 0
    push dword [ebp - 164]     ; alloced mem
    call [virtual_free]

    push dword [ebp - 152]      ; file handle
    call [close_handle]

    mov eax, [ebp - 4]       ; return code

    leave
    ret 8


section .data
%include '../utils/utils_32_data.asm'

ret_val_1_str: db 'Usage: parse_pe.exe <filename> <options>', 0
.len equ $ - ret_val_1_str

ret_val_2_str: db 'ERR: Input file does not exist', 0
.len equ $ - ret_val_2_str

ret_val_3_open_file_str: db 'OpenFile failed', 0
.len equ $ - ret_val_3_open_file_str

ret_val_4_get_file_size_str: db 'GetFileSize failed', 0
.len equ $ - ret_val_4_get_file_size_str

ret_val_5_virtual_alloc_str: db 'VirtualAlloc failed', 0
.len equ $ - ret_val_5_virtual_alloc_str

ret_val_6_read_file_str: db 'ERR: ReadFile failed', 0
.len equ $ - ret_val_6_read_file_str

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

shlwapi_xor: db 0x63, 0x58, 0x5c, 0x47, 0x51, 0x40, 0x59, 0x1e, 0x54, 0x5c, 0x5c, 0
.len equ $ - shlwapi_xor - 1

path_file_exists_a_xor: db 0x60, 0x51, 0x44, 0x58, 0x76, 0x59, 0x5c, 0x55, 0x75, 0x48, 0x59, 0x43, 0x44, 0x43, 0x71, 0
.len equ $ - path_file_exists_a_xor - 1

STD_HANDLE_ENUM equ -11
INVALID_HANDLE_VALUE equ -1
INVALID_FILE_SIZE equ -1
OF_READ equ 0
OF_FILE_STRUCT_SIZE equ 144
DOS_HEADER_BUFFER_SIZE equ 64
NT_FILE_HEADER_BUFFER_SIZE equ 20
OPTIONAL_HEADER_BUFFER_SIZE equ 240 ; 224 bytes 32bit / 240 bytes 64bit

; Virtual Alloc
MEM_COMMIT equ 0x00001000
MEM_RESERVE equ 0x00002000

PAGE_READWRITE equ 0x04
PAGE_EXECUTE_READWRITE equ 0x40

; Virtual Free
MEM_RELEASE equ 0x00008000

section .bss
path_file_exists_a: dd ?
%include '../utils/utils_32_bss.asm'