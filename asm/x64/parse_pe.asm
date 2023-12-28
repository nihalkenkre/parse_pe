section .text
global _parse_pe

%include 'utils_inc_text_64.asm'

extern PathFileExistsA
extern GetLastError
extern OpenFile
extern GetFileSize
extern VirtualAlloc
extern ReadFile
extern VirtualFree
extern CloseHandle

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

    ; [rbp - 8] = current section header
    ; [rbp - 16] = return code
    sub rsp, 16                     ; allocate local variable space

    mov qword [rbp - 16], 0

    mov rcx, [rbp + 32]             ; section header count
    mov rdx, [rbp + 24]             ; section headers
    .loop:
        mov [rbp - 8], rdx          ; current section header

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
        mov rdx, [rbp - 8]          ; section header in rdx

        add rdx, 12                 ; virtual addr
        sub dword eax, [rdx]              ; rva - virtual_addr

        add rdx, 8                  ; raw data ptr
        add dword eax, [rdx]              ; rva - virtual_addr + raw data pointer

        mov [rbp - 16], rax

.shutdown:
    add rsp, 16                     ; free local variable space

    mov rax, [rbp - 16]             ; return code in rax

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
    mov rax, [rbp + 16]             ; section headers in rax

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

    ; [rbp - 8] = offset
    ; 8 bytes padding
    sub rsp, 16                      ; allocate local variable space

    sub rsp, 32
    mov rcx, [rbp + 16]             ; IDT rva
    mov rdx, [rbp + 24]             ; section headers
    mov r8, [rbp + 32]              ; section header count
    call rva_to_offset              ; offset in rax
    add rsp, 32

    cmp rax, 0                      ; offset == 0 ?
    jle .shutdown

    mov [rbp - 8], rax              ; offset saved
    mov rax, [rbp - 8]              ; offset
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
    add rsp, 16                      ; free local variable space

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

    ; [rbp - 8] = offset
    ; 8 bytes padding
    sub rsp, 16                         ; allocate local variable space

    sub rsp, 32
    mov rcx, [rbp + 16]
    mov rdx, [rbp + 24]
    mov r8, [rbp + 32]
    call rva_to_offset                  ; offset in rax
    add rsp, 32

    cmp rax, 0                          ; offset == 0 ?

    jle .shutdown

    mov [rbp - 8], rax                  ; offset saved

    mov rax, [rbp - 8]                  ; offset
    add rax, [rbp + 40]                 ; base + offset

    mov ecx, [rax + 20]                 ; Number of entries in EAT

    ; TODO: Loop through exported functions / names
    
.shutdown:
    add rsp, 16                         ; free local variable space

    leave
    ret

; arg0: base addr file contents   rcx
; arg1: Options                   rdx
parse_pe:
    push rbp
    mov rbp, rsp

    mov [rbp + 16], rcx             ; base addr
    mov [rbp + 24], rdx             ; options

    ; [rbp - 8] = nt header
    ; [rbp - 16] = file header
    ; [rbp - 24] = optional header
    ; [rbp - 32] = section header count
    ; [rbp - 40] = section headers
    ; [rbp - 48] = file bitness 1: 64 bit, 0: 32 bit
    sub rsp, 48                     ; allocate local variable space

    ; retrive and  save the information to the above stack variables
    mov rbx, [rbp + 16]             ; base addr
    add rbx, 0x3c                   ; offset of e_lfanew

    xor rax, rax
    mov word ax, [rbx]              ; e_lfanew in rax

    mov rbx, [rbp + 16]             ; base addr
    add rbx, rax                    ; nt headers

    mov [rbp - 8], rbx              ; nt headers saved
    
    add rbx, 4                      ; file header
    mov [rbp - 16], rbx             ; file header saved

    add rbx, 20                     ; optional header
    mov [rbp - 24], rbx             ; optional header saved

    xor rax, rax
    xor rbx, rbx
    mov rax, [rbp - 24]             ; optional header in rax
    mov bx, [rax]                   ; magic in rbx
    mov bx, [rax + 16]              ; entry point in rbx

    mov rbx, [rbp - 16]             ; file header in rbx
    add rbx, 2
    xor rax, rax
    mov ax, [rbx]
    mov [rbp - 32], rax             ; section header count saved

    mov rbx, [rbp - 16]             ; file header in rbx
    mov bx, [rbx]

    cmp bx, 0x14c                   ; is file 32 bit
    je .32bit
        mov rax, [rbp - 24]         ; optional header in rax
        add rax, 240                ; end of optional header

        mov [rbp - 40], rax         ; section headers saved
        mov qword [rbp - 48], 1     ; file bitness saved

    jmp .continue_bit_check

.32bit:
    mov rax, [rbp - 24]             ; optional header in rax
    add rax, 224                    ; end of optional header

    mov [rbp - 40], rax             ; section headers saved
    mov qword [rbp - 48], 0         ; file bitness saved

.continue_bit_check:
    ; loop section headers
    sub rsp, 32
    mov rcx, [rbp - 40]             ; section headers
    mov rdx, [rbp - 32]             ; section headers count
    call loop_section_headers
    add rsp, 32

.iat:    
    ; loop IDT
    mov rax, [rbp - 24]             ; optional header

    cmp qword [rbp - 48], 0         ; is file 32 bit
    je .32bitidt
        add rax, 120                ; IDT
        mov eax, [eax]

        cmp eax, 0                  ; if IDT rva == 0 ?
        je .edt

        jmp .continue_bitcheck_iat

.32bitidt:
    add rax, 104                    ; IDT
    mov eax, [eax]

    cmp eax, 0                      ; if IDT rva == 0 ?
    je .edt

.continue_bitcheck_idt:
    sub rsp, 32
    mov ecx, eax
    mov rdx, [rbp - 40]
    mov r8, [rbp - 32]
    mov r9, [rbp + 16]
    call loop_import_descriptor_table
    add rsp, 32

.edt:
    ; loop EDT
    int3
    mov rax, [rbp - 24]             ; optional header
    cmp qword [rbp - 48], 0         ; is file 32 bit

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
    sub rsp, 32
    mov ecx, eax
    mov rdx, [rbp - 40]
    mov r8, [rbp - 32]
    mov r9, [rbp + 16]
    call loop_export_descriptor_table
    add rsp, 32

.shutdown:
    add rsp, 48                     ; free local variable space

    leave
    ret


; arg0: argc            rcx
; arg1: argv            rdx
_parse_pe:
    push rbp
    mov rbp, rsp

    ; [rbp + 16] = argc, [rbp + 24] = argv

    mov [rbp + 16], rcx              ; argc in [rbp - 8]
    mov [rbp + 24], rdx              ; argv in [rbp - 16]

    ; [rbp - OF_FILE_STRUCT_SIZE] = OFFILESTRUCT
    ; [rbp - OF_FILE_STRUCT_SIZE - 8] = file handle
    ; [rbp - OF_FILE_STRUCT_SIZE - 16] = getfilesize high order dw of file size
    ; [rbp - OF_FILE_STRUCT_SIZE - 24] = getfilesize low order dw of file size
    ; [rpb - OF_FILE_STRUCT_SIZE - 32] = allocated mem for input file read
    ; [rbp - OF_FILE_STRUCT_SIZE - 40] = return code
    ; 8 bytes
    sub rsp, OF_FILE_STRUCT_SIZE + 48     ; allocate local variable space
    mov qword [rbp - OF_FILE_STRUCT_SIZE - 40], 0

    cmp byte [rbp + 16], 3           ; argc == 3 ?

    je .continue_argc_check
        lea rcx, ret_val_1_str
        mov rdx, ret_val_1_str.len
        sub rsp, 32
        call print_string
        add rsp, 32

        sub rsp, 32
        call GetLastError
        add rsp, 32
            
        mov qword [rbp - OF_FILE_STRUCT_SIZE - 40], 1

        jmp .shutdown

    .continue_argc_check:
        xor rdx, rdx
        mov rdx, [rbp + 24]         ; argv in rdx
        mov rdx, [rdx + 8]          ; argv[1] in rdx

        mov rcx, rdx
        sub rsp, 32
        call PathFileExistsA
        add rsp, 32

        cmp eax, 1                  ; does file exist
        je .continue_path_file_check
            lea rcx, ret_val_2_str
            mov rdx, ret_val_2_str.len
            sub rsp, 32
            call print_string
            add rsp, 32

            sub rsp, 32
            call GetLastError
            add rsp, 32

            mov qword [rbp - OF_FILE_STRUCT_SIZE - 40], 2

            jmp .shutdown

    .continue_path_file_check:

        xor rdx, rdx
        mov rdx, [rbp + 24]         ; argv in rdx
        add rdx, 8                  ; command line FileName in rdx
        mov rcx, [rdx]

        mov rdx, rsp
        sub rdx, OF_FILE_STRUCT_SIZE  ; addr of struct in rdx
        xor r8, r8

        sub rsp, 32
        call OpenFile                 ; file handle in rax
        add rsp, 32

        cmp rax, INVALID_HANDLE_VALUE
        jne .continue_open_file
            mov rcx, ret_val_3_open_file_str
            mov rdx, ret_val_3_open_file_str.len
            sub rsp, 32
            call print_string
            add rsp, 32

            sub rsp, 32
            call GetLastError
            add rsp, 32

            mov qword [rbp - OF_FILE_STRUCT_SIZE - 40], 3

            jmp .shutdown

    .continue_open_file:
        mov qword [rbp - OF_FILE_STRUCT_SIZE - 8], rax      ; file handle saved
        
        mov rcx, [rbp - OF_FILE_STRUCT_SIZE - 8]
        mov rdx, rbp
        sub rdx, OF_FILE_STRUCT_SIZE + 16
        sub rsp, 32
        call GetFileSize                ; file size in rax
        add rsp, 32 

        cmp rax, INVALID_FILE_SIZE
        jne .continue_get_file_size
            mov rcx, ret_val_4_get_file_size_str
            mov rdx, ret_val_4_get_file_size_str.len
            sub rsp, 32
            call print_string
            add rsp, 32

            sub rsp, 32
            call GetLastError
            add rsp, 32

            mov qword [rbp - OF_FILE_STRUCT_SIZE - 40], 4

            jmp .shutdown

    .continue_get_file_size:
        mov qword [rbp - OF_FILE_STRUCT_SIZE - 24], rax         ; file size saved

        xor rcx, rcx
        mov rdx, [rbp - OF_FILE_STRUCT_SIZE - 24]
        mov r8, MEM_COMMIT
        or r8, MEM_RESERVE
        mov r9, PAGE_READWRITE
        sub rsp, 32
        call VirtualAlloc                       ; allocated addr in rax
        add rsp, 32

        cmp rax, 0                              ; if addr == NULL
        jne .continue_virtual_alloc
            mov rcx, ret_val_5_virtual_alloc_str
            mov rdx, ret_val_5_virtual_alloc_str.len
            sub rsp, 32
            call print_string
            add rsp, 32

            sub rsp, 32
            call GetLastError
            add rsp, 32

            mov qword [rbp - OF_FILE_STRUCT_SIZE - 40], 5

            jmp .shutdown

    .continue_virtual_alloc:
        mov qword [rbp - OF_FILE_STRUCT_SIZE - 32], rax     ; alloc addr saved

        sub rsp, 48
        mov rcx, [rbp - OF_FILE_STRUCT_SIZE - 8]
        mov rdx, [rbp - OF_FILE_STRUCT_SIZE - 32]
        mov r8, [rbp - OF_FILE_STRUCT_SIZE - 24]
        xor r9, r9
        mov qword [rsp + 32], 0
        call ReadFile
        add rsp, 48

        cmp rax, 1                            ; 1: successful read
        je .continue_read_file
            sub rsp, 32
            lea rcx, ret_val_6_read_file_str
            mov rdx, ret_val_6_read_file_str.len
            call print_string
            add rsp, 32

            sub rsp, 32
            call GetLastError
            add rsp, 32

            mov qword [rbp - OF_FILE_STRUCT_SIZE - 40], 6

            jmp .shutdown

    .continue_read_file:
        
        sub rsp, 32
        mov rcx, [rbp - OF_FILE_STRUCT_SIZE - 32]
        mov rdx, [rbp + 24]         ; argv in rdx
        add rdx, 16                 ; command line Options in rdx
        mov rdx, [rdx]
        call parse_pe
        add rsp, 32

.shutdown:
    sub rsp, 32
    mov rcx, [rbp - OF_FILE_STRUCT_SIZE - 32]
    xor rdx, rdx 
    mov r8, MEM_RELEASE
    call VirtualFree
    add rsp, 32

    sub rsp, 32
    mov rcx, [rbp - OF_FILE_STRUCT_SIZE - 8]
    call CloseHandle
    add rsp, 32

    mov rax, [rbp - OF_FILE_STRUCT_SIZE - 40]       ; return code

    add rsp, OF_FILE_STRUCT_SIZE + 48    ; free local variable space

    leave
    ret

section .data
%include 'utils_inc_data_64.asm'

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