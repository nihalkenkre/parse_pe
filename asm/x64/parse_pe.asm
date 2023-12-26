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


; arg0: return addr for optional header     rcx
; arg1: optional header size                rdx
; arg2: file type 1: 64 bit 0: 32 bit       r8
;
; return: addr for optional header          rax
;
; file handle                               r12
parse_nt_header_optional_header:
    push rbp
    mov rbp, rsp

;     mov [rbp + 16], rcx
;     mov [rbp + 24], rdx
;     mov [rbp + 32], r8

;     sub rsp, 32 + 8 + 8
;     mov rcx, r12
;     mov rdx, [rbp + 16]
;     mov r8, [rbp + 24]                 ; bytes to read actual size
;     xor r9, r9
;     mov qword [rsp + 32], 0
;     call ReadFile
;     add rsp, 32 + 8 + 8

;     cmp rax, 1                          ; if ReadFile is successful
;     je .continue
;         sub rsp, 32
;         lea rcx, ret_val_9_nt_header_optional_header_str
;         mov rdx, ret_val_9_nt_header_optional_header_str.len
;         call print_string
;         add rsp, 32

;         sub rsp, 32
;         call GetLastError
;         add rsp, 32

;         jmp .shutdown

; .continue:

; .shutdown:

    ; mov rax, [rbp + 16]                 ; return addr in rax

    leave
    ret


; arg0: return addr for file header         rcx
;
; return: return addr for file header       rax
;
; file handle                               r12
parse_nt_header_file_header:
    push rbp
    mov rbp, rsp

    ; mov [rbp + 16], rcx                  ; return addr in [rbp + 16]

;     sub rsp, 32 + 8 + 8
;     mov rcx, r12                        ; file handle as arg
;     mov rdx, [rbp + 16]
;     mov r8, 20                           ; bytes to read, actual size
;     xor r9, r9
;     mov qword [rsp + 32], 0
;     call ReadFile
;     add rsp, 32 + 8 + 8

;     cmp rax, 1                            ; 1: successful read
;     je .continue
;         sub rsp, 32
;         lea rcx, ret_val_7_nt_header_file_header_str
;         mov rdx, ret_val_7_nt_header_file_header_str.len
;         call print_string
;         add rsp, 32

;         sub rsp, 32
;         call GetLastError
;         add rsp, 32

;         jmp .shutdown
; .continue:

; .shutdown:
;     mov rax, [rbp + 16]                 ; return addr in rax

    leave
    ret

; file handle           r12
parse_nt_header_signature:
    push rbp
    mov rbp, rsp

    ; [rbp - 16] = signature
;     sub rsp, 16                         ; allocate local variable space

;     sub rsp, 32 + 8 + 8
;     mov rcx, r12
;     mov rdx, rbp
;     sub rdx, 16
;     mov r8, 4
;     xor r9, r9
;     mov qword [rsp + 32], 0
;     call ReadFile
;     add rsp, 32 + 8 + 8

;     cmp rax, 1                            ; 1: successful read
;     je .continue
;         sub rsp, 32
;         lea rcx, ret_val_6_nt_header_signature_str
;         mov rdx, ret_val_6_nt_header_signature_str.len
;         call print_string
;         add rsp, 32

;         sub rsp, 32
;         call GetLastError
;         add rsp, 32

;         jmp .shutdown

; .continue:
;     ; sub rsp, 32
;     ; mov rcx, rbp
;     ; sub rcx, 16
;     ; mov rdx, 4
;     ; call print_string
;     ; add rsp, 32

; .shutdown:
;     add esp, 16

    leave
    ret

; arg1: stub size           rcx
; file handle               r12
parse_dos_stub:
    push rbp
    mov rbp, rsp

    ; [rbp + 16] = stub size
;     mov [rbp + 16], rcx

;     ; [rbp - 256] = dos stub
;     sub rsp, 256                        ; allocate local variable space

;     sub rsp, 32 + 8 + 8

;     mov rcx, r12                        ; file handle
;     mov rdx, rbp
;     sub rdx, 256                        ; output buffer
;     mov r8, [rbp + 16]                  ; number of bytes to read
;     xor r9, r9                          ; 0
;     mov qword [rsp + 32], 0             ; 0
;     call ReadFile

;     add rsp, 32 + 8 + 8

;     cmp rax, 1                            ; 1: successful read
;     je .continue
;         sub rsp, 32
;         lea rcx, ret_val_5_dos_stub_str
;         mov rdx, ret_val_5_dos_stub_str.len
;         call print_string
;         add rsp, 32

;         sub rsp, 32
;         call GetLastError
;         add rsp, 32

;         jmp .shutdown
    
; .continue:
;     ; sub rsp, 32
;     ; mov rcx, rbp
;     ; sub rcx, 256
;     ; mov rdx, [rbp + 16]
;     ; call print_string
;     ; add rsp, 32
    
; .shutdown:
;     add rsp, 256                         ; free local variable space

    leave
    ret


; file handle             r12
;
; arg0: return addr for my dos header      rcx
;
; return: return addr for my dos header    rax
parse_dos_header:
    push rbp
    mov rbp, rsp

    ; [rbp + 16] = return addr
;     mov [rbp + 16], rcx

;     sub rsp, 32 + 8 + 8
;     mov rcx, r12
;     mov rdx, [rbp + 16]
;     mov r8, DOS_HEADER_BUFFER_SIZE
;     xor r9, r9
;     mov qword [rsp + 32], 0
;     call ReadFile
;     add rsp, 32 + 8 + 8

;     cmp rax, 1                      ; if (ReadFile....)
;     je .continue
;         sub rsp, 32
;         lea rcx, ret_val_4_dos_header_str
;         mov rdx, ret_val_4_dos_header_str.len
;         call print_string
;         add rsp, 32

;         sub rsp, 32
;         call GetLastError
;         add rsp, 32

;         jmp .shutdown

; .continue:
;     mov rax, [rbp + 16]

; .shutdown:

    leave
    ret

; arg0: mem addr file contents    rcx
; arg1: Options                   rdx
parse_pe:
    push rbp
    mov rbp, rsp

    mov [rbp + 16], rcx
    mov [rbp + 24], rdx

    int3

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
    ; [rpb - OF_FILE_STRUCT_SIZE - 32] = allocated address for input file read
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
    int3
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

ret_val_2_str: db 'ERR: Input file not exist', 0
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