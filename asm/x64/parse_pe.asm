section .text
global _parse_pe

%include '../utils/utils_64_text.asm'

; arg0: rva                     rcx
; arg1: section headers         rdx
; arg2: section header count    r8 
;
; return: offset                rax > 0
rva_to_offset:
    push rbp
    mov rbp, rsp

    mov [rbp + 16], rcx             ; rva
    mov [rbp + 24], rdx             ; section headers
    mov [rbp + 32], r8              ; section header count

    ; rbp - 8 = return code
    ; rbp - 16 = current section header
    sub rsp, 16                     ; allocate local variable space

    mov qword [rbp - 8], 0          ; return value

    mov rcx, [rbp + 32]             ; section header count
    mov rdx, [rbp + 24]             ; section headers
    .loop:
        mov [rbp - 16], rdx         ; current section header

        add rdx, 12                 ; virtual addr
        mov eax, [rdx]              ; virtual addr in rax
        add rdx, 4                  ; size of raw data

        add eax, [rdx]              ; rax = virtual addr + raw data size

        cmp rax, [rbp + 16]         ; x >= rva
        jge .return_offset

        add rdx, 24                 ; add size of section header, next section header

        dec rcx
        cmp rcx, 0
        jnz .loop

        jmp .shutdown

    .return_offset:
        mov rax, [rbp + 16]         ; rva in rax
        mov rdx, [rbp - 16]         ; section header in rdx

        add rdx, 12                 ; virtual addr
        sub dword eax, [rdx]        ; rva - virtual_addr

        add rdx, 8                  ; raw data ptr
        add dword eax, [rdx]        ; rva - virtual_addr + raw data pointer

        mov [rbp - 16], rax         ; current section header

.shutdown:

    mov rax, [rbp - 8]              ; return value

    leave
    ret

; arg0: section headers             rcx
; arg1: section header count        rdx
loop_section_headers:
    push rbp
    mov rbp, rsp

    mov [rbp + 16], rcx             ; section headers
    mov [rbp + 24], rdx             ; section header count

    mov rcx, [rbp + 24]             ; section header count
    mov rax, [rbp + 16]             ; section headers

    .loop:
        add rax, 40                 ; add section header size (next section header)

        dec rcx
        cmp rcx, 0
        jnz .loop

    leave
    ret

; arg0: import descriptor table rva     rcx
; arg1: section headers                 rdx
; arg2: section header count            r8
; arg3: file contents base addr         r9
loop_import_descriptor_table:
    push rbp
    mov rbp, rsp

    mov [rbp + 16], rcx             ; IDT rva
    mov [rbp + 24], rdx             ; section headers
    mov [rbp + 32], r8              ; section header count
    mov [rbp + 40], r9              ; file contents base addr

    ; rbp - 8 = return value
    ; rbp - 16 = offset
    sub rsp, 16                     ; allocate local variable space
    sub rsp, 32                     ; allocate shadow space

    mov rcx, [rbp + 16]             ; IDT rva
    mov rdx, [rbp + 24]             ; section headers
    mov r8, [rbp + 32]              ; section header count
    call rva_to_offset              ; offset in rax

    cmp rax, 0                      ; offset == 0 ?
    jle .shutdown

    mov [rbp - 16], rax             ; offset saved
    mov rax, [rbp - 16]             ; offset
    add rax, [rbp + 40]             ; base + offset
    .loop:
        add rax, 12                 ; Name RVA
        cmp dword [rax], 0
        je .loop_end

        add rax, 8                  ; next IDT

        jmp .loop

    ; TODO: Loop through functions of each imported DLL

.loop_end:

.shutdown:

    mov rax, [rbp - 8]                  ; return value

    leave
    ret

; arg0: export directory table rva      rcx
; arg1: section headers                 rdx
; arg2: section header count            r8
; arg3: file contents base addr         r9
loop_export_descriptor_table:
    push rbp
    mov rbp, rsp

    mov [rbp + 16], rcx                 ; EDT rva
    mov [rbp + 24], rdx                 ; section headers
    mov [rbp + 32], r8                  ; section header count
    mov [rbp + 40], r9                  ; file contents base addr

    ; rbp - 8 = return value
    ; rbp - 16 = offset
    sub rsp, 16                         ; allocate local variable space
    sub rsp, 32                         ; allocate shadow space

    mov rcx, [rbp + 16]
    mov rdx, [rbp + 24]
    mov r8, [rbp + 32]
    call rva_to_offset                  ; offset in rax

    cmp rax, 0                          ; offset == 0 ?

    jle .shutdown

    mov [rbp - 16], rax                 ; offset saved

    mov rax, [rbp - 16]                 ; offset
    add rax, [rbp + 40]                 ; base + offset

    mov ecx, [rax + 20]                 ; Number of entries in EAT

    ; TODO: Loop through exported functions / names
    
.shutdown:

    mov rax, [rbp - 8]                  ; return value

    leave
    ret

; arg0: base addr file contents   rcx
; arg1: Options                   rdx
parse_pe:
    push rbp
    mov rbp, rsp

    mov [rbp + 16], rcx             ; base addr
    mov [rbp + 24], rdx             ; options

    ; rbp - 8 = return value
    ; rbp - 16 = nt header
    ; rbp - 24 = file header
    ; rbp - 32 = optional header
    ; rbp - 40 = section header count
    ; rbp - 48 = section headers
    ; rbp - 56 = file bitness 1: 64 bit, 0: 32 bit
    ; rbp - 64 = 8 bytes padding
    sub rsp, 64                     ; allocate local variable space
    sub rsp, 32                     ; allocate shadow space

    mov qword [rbp - 8], 0          ; return value

    ; retrive and  save the information to the above stack variables
    mov rbx, [rbp + 16]             ; base addr
    add rbx, 0x3c                   ; offset of e_lfanew

    movzx eax, word [rbx]           ; e_lfanew in rax

    mov rbx, [rbp + 16]             ; base addr
    add rbx, rax                    ; nt headers

    mov [rbp - 16], rbx              ; nt headers saved
    
    add rbx, 4                      ; file header
    mov [rbp - 24], rbx             ; file header saved

    add rbx, 20                     ; optional header
    mov [rbp - 32], rbx             ; optional header saved

    mov rax, [rbp - 32]             ; optional header in rax
    movzx ebx, word [rax]           ; magic in rbx
    mov ebx, dword [rax + 16]       ; entry point in rbx

    mov rbx, [rbp - 24]             ; file header in rbx
    add rbx, 2
    movzx eax, word [rbx]
    mov [rbp - 40], rax             ; section header count saved

    mov rbx, [rbp - 24]             ; file header in rbx
    movzx ebx, word [rbx]

    cmp rbx, 0x14c                  ; is file 32 bit
    je .32bit
        mov rax, [rbp - 32]         ; optional header in rax
        add rax, 240                ; end of optional header

        mov [rbp - 48], rax         ; section headers saved
        mov qword [rbp - 56], 1     ; file bitness saved

    jmp .continue_bit_check

.32bit:
    mov rax, [rbp - 32]             ; optional header in rax
    add rax, 224                    ; end of optional header

    mov [rbp - 48], rax             ; section headers saved
    mov qword [rbp - 56], 0         ; file bitness saved

.continue_bit_check:
    ; loop section headers
    mov rcx, [rbp - 48]             ; section headers
    mov rdx, [rbp - 40]             ; section headers count
    call loop_section_headers

.iat:    
    ; loop IDT
    mov rax, [rbp - 32]             ; optional header

    cmp qword [rbp - 56], 0         ; is file 32 bit
    je .32bitidt
        add rax, 120                ; IDT
        mov eax, [eax]

        cmp eax, 0                  ; if IDT rva == 0 ?
        je .edt

        jmp .continue_bitcheck_idt

.32bitidt:
    add rax, 104                    ; IDT
    mov eax, [eax]

    cmp eax, 0                      ; if IDT rva == 0 ?
    je .edt

.continue_bitcheck_idt:
    mov ecx, eax                    ; rva
    mov rdx, [rbp - 48]             ; section headers
    mov r8, [rbp - 40]              ; section header count
    mov r9, [rbp + 16]              ; file contents base addr
    call loop_import_descriptor_table

.edt:
    ; loop EDT
    mov rax, [rbp - 32]             ; optional header
    cmp qword [rbp - 56], 0         ; is file 32 bit

    je .32bitedt
        add rax, 112                ; EDT
        mov eax, [eax]

        cmp eax, 0                  ; if EDT rva == 0 ?
        je .shutdown

        jmp .continue_bitcheck_edt

.32bitedt:
    add rax, 96                     ; EDT
    mov eax, [eax]

    cmp eax, 0                      ; if EDT rva == 0 ?
    je .shutdown

.continue_bitcheck_edt:
    mov ecx, eax                    ; rva
    mov rdx, [rbp - 48]             ; section headers
    mov r8, [rbp - 40]              ; section header count
    mov r9, [rbp + 16]              ; file contents base addr
    call loop_export_descriptor_table

.shutdown:

    mov rax, [rbp - 8]              ; return value

    leave
    ret


; arg0: argc            rcx
; arg1: argv            rdx
_parse_pe:
    push rbp
    mov rbp, rsp

    mov [rbp + 16], rcx              ; argc in [rbp - 8]
    mov [rbp + 24], rdx              ; argv in [rbp - 16]

    ; rbp - 8 = return value
    ; rbp - 152 = OFSTRUCT
    ; rbp - 160 = file handle
    ; rbp - 168 = getfilesize high order dw of file size
    ; rbp - 176 = getfilesize low order dw of file size
    ; rbp - 184 = ptr to allocated me for file contents
    ; rbp - 192 = kernel handle
    ; rbp - 200 = std handle
    ; rbp - 208 = shlwapi addr
    sub rsp, 208                    ; allocate local variable space
    sub rsp, 32                     ; allocate shadow space

    mov qword [rbp - 8], 0          ; return value

    call get_kernel_module_handle
    mov [rbp - 192], rax            ; kernel handle

    mov rcx, [rbp - 192]            ; kernel handle
    call populate_kernel_function_ptrs_by_name

    cmp byte [rbp + 16], 3          ; argc == 3 ?

    je .continue_argc_check
        mov rcx, STD_HANDLE_ENUM
        call [get_std_handle]

        mov [rbp - 200], rax            ; std handle

        mov rcx, [rbp - 200]            ; std handle
        mov rdx, ret_val_1_str
        mov r8, ret_val_1_str.len
        call print_string

        call [get_last_error]

        mov qword [rbp - 8], 1

        jmp .shutdown

    .continue_argc_check:

        mov rcx, shlwapi_xor
        mov rdx, shlwapi_xor.len
        mov r8, xor_key
        mov r9, xor_key.len
        call my_xor

        mov rcx, shlwapi_xor
        call [load_library_a]
        
        cmp rax, 0
        je .shutdown
        mov [rbp - 208], rax            ; shlwapi addr

        mov rcx, path_file_exists_a_xor
        mov rdx, path_file_exists_a_xor.len
        mov r8, xor_key
        mov r9, xor_key.len
        call my_xor

        mov rcx, [rbp - 208]
        mov rdx, path_file_exists_a_xor
        call get_proc_address_by_get_proc_addr

        cmp rax, 0
        je .shutdown

        mov [path_file_exists_a], rax

        mov rcx, [rbp + 24]         ; argv in rcx
        mov rcx, [rcx + 8]          ; argv[1] in rcx
        call [path_file_exists_a]

        cmp eax, 1                  ; does file exist
        je .continue_path_file_check
            mov rcx, STD_HANDLE_ENUM
            call [get_std_handle]

            mov [rbp - 200], rax            ; std handle

            mov rcx, [rbp - 200]            ; std handle
            mov rdx, ret_val_2_str
            mov r8, ret_val_2_str.len
            call print_string

            call [get_last_error]

            mov qword [rbp - 8], 2

            jmp .shutdown

    .continue_path_file_check:

        mov rdx, [rbp + 24]         ; argv in rdx
        add rdx, 8                  ; command line FileName in rdx
        mov rcx, [rdx]

        mov rdx, rsp
        sub rdx, 152                ; addr of struct in rdx
        xor r8, r8

        call [open_file]                 ; file handle in rax

        cmp rax, INVALID_HANDLE_VALUE
        jne .continue_open_file
            mov rcx, STD_HANDLE_ENUM
            call [get_std_handle]

            mov [rbp - 200], rax            ; std handle

            mov rcx, [rbp - 200]            ; std handle
            mov rdx, ret_val_3_open_file_str
            mov r8, ret_val_3_open_file_str.len
            call print_string

            call [get_last_error]

            mov qword [rbp - 8], 3

            jmp .shutdown

    .continue_open_file:
        mov qword [rbp - 160], rax      ; file handle saved
        
        mov rcx, [rbp - 160]            ; file handle
        mov rdx, rbp
        sub rdx, 168                    ; file size high
        call [get_file_size]            ; file size in rax

        cmp rax, INVALID_FILE_SIZE
        jne .continue_get_file_size
            mov rcx, STD_HANDLE_ENUM
            call [get_std_handle]

            mov [rbp - 200], rax            ; std handle

            mov rcx, [rbp - 200]            ; std handle
            mov rdx, ret_val_4_get_file_size_str
            mov r8, ret_val_4_get_file_size_str.len
            call print_string

            call [get_last_error]

            mov qword [rbp - 8], 4

            jmp .shutdown

    .continue_get_file_size:
        mov qword [rbp - 176], rax              ; file size saved

        xor rcx, rcx
        mov rdx, [rbp - 176]                    ; dw file size
        mov r8, MEM_COMMIT
        or r8, MEM_RESERVE
        mov r9, PAGE_READWRITE
        call [virtual_alloc]                       ; allocated addr in rax

        cmp rax, 0                              ; if addr == NULL
        jne .continue_virtual_alloc
            mov rcx, STD_HANDLE_ENUM
            call [get_std_handle]

            mov [rbp - 200], rax                 ; std handle

            mov rcx, [rbp - 200]                ; std handle
            mov rdx, ret_val_5_virtual_alloc_str
            mov r8, ret_val_5_virtual_alloc_str.len
            call print_string

            call [get_last_error]

            mov qword [rbp - 8], 5

            jmp .shutdown

    .continue_virtual_alloc:
        mov qword [rbp - 184], rax              ; alloc addr saved

        sub rsp, 16                             ; 1 arg + 8 byte padding
        mov rcx, [rbp - 160]                    ; file handle
        mov rdx, [rbp - 184]                    ; ptr to allocated mem
        mov r8, [rbp - 176]                     ; n Bytes to read
        xor r9, r9
        mov qword [rsp + 32], 0
        call [read_file]
        add rsp, 16                             ; 1 arg + 8 byte padding

        cmp rax, 1                              ; 1: successful read
        je .continue_read_file
            mov rcx, STD_HANDLE_ENUM
            call [get_std_handle]

            mov [rbp - 200], rax                 ; std handle

            mov rcx, [rbp - 200]                ; std handle
            mov rdx, ret_val_6_read_file_str
            mov r8, ret_val_6_read_file_str.len
            call print_string

            call [get_last_error]

            mov qword [rbp - 8], 6

            jmp .shutdown

    .continue_read_file:
        
        mov rcx, [rbp - 184]        ; base addr of file
        mov rdx, [rbp + 24]         ; argv in rdx
        add rdx, 16                 ; command line Options in rdx
        mov rdx, [rdx]
        call parse_pe

.shutdown:
    mov rcx, [rbp - 184]            ; ptr to file contents
    xor rdx, rdx 
    mov r8, MEM_RELEASE
    call [virtual_free]

    mov rcx, [rbp - 160]            ; file handle
    call [close_handle]

    mov rax, [rbp - 8]       ; return code

    leave
    ret

section .data
%include '../utils/utils_64_data.asm'

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
NT_FILE_HEADER_BUFFER_SIZE equ 32   ; 20 + 12 bytes padding to make it divisible by 16
OPTIONAL_HEADER_BUFFER_SIZE equ 256 ; 224 bytes / 240 bytes is required for 32 bit / 64 bit, padding byte to make it divisible by 16

; Virtual Alloc
MEM_COMMIT equ 0x00001000
MEM_RESERVE equ 0x00002000

PAGE_READWRITE equ 0x04
PAGE_EXECUTE_READWRITE equ 0x40

; Virtual Free
MEM_RELEASE equ 0x00008000

section .bss
path_file_exists_a: dq ?
%include '../utils/utils_64_bss.asm'