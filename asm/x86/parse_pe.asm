section .text
global _parse_pe

%include 'utils_inc_text_32.asm'

extern _PathFileExistsA@4
extern _GetLastError@0
extern _OpenFile@12
extern _GetFileSize@8
extern _VirtualAlloc@16
extern _ReadFile@20
extern _VirtualFree@12
extern _CloseHandle@4

; arg0: rva                         [ebp + 8]
; arg1: section headers             [ebp + 12]
; arg2: section header count        [ebp + 16]
;
; returns offset                    rax > 0
rva_to_offset:
    push ebp
    mov ebp, esp

    ; [ebp - 4] = current section header
    ; [ebp - 8] = return code
    sub esp, 8                      ; allocate local variable space

    mov dword [ebp - 8], 0          ; return code

    mov ecx, [ebp + 16]             ; section header count
    mov edx, [ebp + 12]             ; section headers

    .loop:
        mov [ebp - 4], edx          ; current section header
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
        mov edx, [ebp - 4]          ; current section header

        add edx, 12                 ; virtual addr
        sub eax, [edx]              ; rva - virtual addr

        add edx, 8                  ; raw data ptr
        add eax, [edx]              ; rva - virtual addr + raw data pointer

        mov [ebp - 8], eax
    
.shutdown:
    add esp, 8                      ; free local variable space
    add esp, 12                     ; free arg stack

    mov eax, [ebp - 8]

    leave
    ret

; arg0: section headers             [ebp + 8]
; arg1: section header count        [ebp + 12]
loop_section_headers:
    push ebp
    mov ebp, esp

    mov ecx, [ebp + 12]             ; section header count
    mov edx, [ebp + 8]              ; section headers

    .loop:
        add edx, 40                 ; add section header size (next section header)

        dec ecx
        cmp ecx, 0
        jnz .loop

    add esp, 8                      ; free arg stack

    leave
    ret

; arg0: import descriptor table rva     [ebp + 8]
; arg1: section headers                 [ebp + 12]
; arg2: section header count            [ebp + 16]
; arg3: base addr file contents         [ebp + 20]
loop_import_descriptor_table:
    push ebp
    mov ebp, esp

    ; [ebp - 4] = offset
    sub esp, 4                      ; allocate local variable space

    push dword [ebp + 16]                 ; section header count
    push dword [ebp + 12]                 ; section headers
    push dword [ebp + 8]                  ; IDT rva
    call rva_to_offset              ; offset in eax

    cmp eax, 0                      ; offset == 0 ?
    jle .shutdown

    mov [ebp - 4], eax              ; offset
    mov eax, [ebp + 20]             ; base addr
    add eax, [ebp - 4]              ; base addr + offset
        
    .loop:
        add eax, 12                 ; name RVA
        cmp dword [eax], 0
        je .loop_end

        add eax, 8                  ; next IDT
        jmp .loop

    ; TODO: Loop through functions of each imported DLL

.loop_end:

.shutdown:
    add esp, 4                      ; free local variable space
    add esp, 16                     ; free arg stack

    leave
    ret

; arg0: export directory table rva      [ebp + 8]
; arg1: section headers                 [ebp + 12]
; arg2: section header count            [ebp + 16]
; arg3: file contents base addr         [ebp + 20]
loop_export_descriptor_table:
    push ebp
    mov ebp, esp

    ; [ebp - 4] = offset
    sub esp, 4                      ; allocate local variable space

    push dword [ebp + 16]                 ; section header count
    push dword [ebp + 12]                 ; section headers
    push dword [ebp + 8]                  ; IDT rva
    call rva_to_offset              ; offset in eax

    cmp eax, 0                      ; offset == 0 ?
    jle .shutdown

    mov [ebp - 4], eax              ; offset
    mov eax, [ebp + 20]             ; base addr
    add eax, [ebp - 4]              ; base + offset

    mov ecx, [eax + 20]             ; number of entries in eat
    
    ; TODO: Loop through exported functions / names


.shutdown:
    add esp, 4                      ; free local variable space
    add esp, 16                     ; free arg stack

    leave
    ret

; arg0: base addr file contents      [ebp + 8]
; arg1: Options                      [ebp + 12]
parse_pe:
    push ebp
    mov ebp, esp

    ; [ebp - 4] = nt header
    ; [ebp - 8] = file header
    ; [ebp - 12] = optional header
    ; [ebp - 16] = section header count
    ; [ebp - 20] = section headers
    ; [ebp - 24] = file bitness 1: 64 bit, 0: 32 bit
    sub esp, 24                     ; allocate local variable space

    ; retrive and  save the information to the above stack variables
    mov ebx, [ebp + 8]              ; base addr
    add ebx, 0x3c                   ; offset of e_lfanew
    movzx eax, word [ebx]                   ; e_lfanew

    mov ebx, [ebp + 8]
    add ebx, eax                    ; nt headers
    mov [ebp - 4], ebx              ; nt headers saved

    add ebx, 4                      ; file header
    mov [ebp - 8], ebx              ; file header saved

    add ebx, 2                      ; section header count 
    movzx eax, word [ebx]
    mov [ebp - 16], eax             ; section header count saved

    add ebx, 18                     ; optional header
    mov [ebp - 12], ebx             ; optional header saved
    
    mov eax, [ebp - 8]              ; file header
    mov ax, [eax]
    cmp word ax, 0x14c              ; is file 32 bit
    je .32bit
        mov eax, [ebp - 12]
        add eax, 240                ; end of optional header, start of section headers

        mov [ebp - 20], eax         ; section headers
        mov dword [ebp - 24], 1     ; file bitness 1 for 64 bit

        jmp .continue_32_bit

    .32bit:
        mov eax, [ebp - 12]
        add eax, 224                ; end of optional header, start of section header

        mov [ebp - 20], eax
        mov dword [ebp - 24], 0     ; file bitness 0 for 32 bit

.continue_32_bit:
    ; loop section headers

    push dword [ebp - 16]           ; section header count
    push dword [ebp - 20]           ; section headers
    call loop_section_headers

.idt:
    ; loop IDT
    mov eax, [ebp - 12]             ; optional header

    cmp dword [ebp - 24], 0         ; is file 32 bit
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
    push dword [ebp - 16]               ; section header count
    push dword [ebp - 20]               ; section headers
    push eax                            ; IDT rva
    call loop_import_descriptor_table

.edt:
    ; loop EDT
    mov eax, [ebp - 12]             ; optional header

    cmp dword [ebp - 24], 0         ; is file 32 bit
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
    push dword [ebp - 16]               ; section header count
    push dword [ebp - 20]               ; section headers
    push eax                            ; EDT rva
    call loop_export_descriptor_table

.shutdown:
    add esp, 24                     ; free local variable space

    leave
    ret

; arg0: argc        [ebp + 8]
; arg1: *argv[]     [ebp + 12]
_parse_pe:
    push ebp
    mov ebp, esp
    ; [ebp - OF_FILE_STRUCT_SIZE] = OFFILESTRUCT
    ; [ebp - OF_FILE_STRUCT_SIZE - 4] = file handle
    ; [ebp - OF_FILE_STRUCT_SIZE - 8] = getfilesize high order dw of file size
    ; [ebp - OF_FILE_STRUCT_SIZE - 12] = getfilesize low order dw of file size
    ; [ebp - OF_FILE_STRUCT_SIZE - 16] = allocated mem for input file read
    ; [ebp - OF_FILE_STRUCT_SIZE - 20] = return code
    sub esp, OF_FILE_STRUCT_SIZE + 20       ; allocate local variable space

    mov dword [ebp - OF_FILE_STRUCT_SIZE - 20], 0

    cmp byte [ebp + 8], 3                   ; argc == 3 ?
    je .continue_argc_check
        push ret_val_1_str.len
        push ret_val_1_str
        call print_string

        call _GetLastError@0

        mov dword [ebp - OF_FILE_STRUCT_SIZE - 20], 1

        jmp .shutdown

.continue_argc_check:
    mov edx, [ebp + 12]                     ; argv in edx
    mov edx, [edx + 4]                      ; argv[1] in edx

    push edx
    call _PathFileExistsA@4

    cmp eax, 1                              ; does file exist
    je .continue_path_file_check
        push ret_val_2_str.len
        push ret_val_2_str
        call print_string

        call _GetLastError@0

        mov dword [ebp - OF_FILE_STRUCT_SIZE - 20], 2

        jmp .shutdown

.continue_path_file_check:
    push 0

    mov edx, esp
    sub edx, OF_FILE_STRUCT_SIZE
    push edx

    mov edx, [ebp + 12]                             ; argv
    add edx, 4                                      ; argv + 1
    push dword [edx]                                ; argv[1]

    call _OpenFile@12                               ; file handle in eax

    cmp eax, INVALID_HANDLE_VALUE
    jne .continue_open_file
        push ret_val_3_open_file_str.len
        push ret_val_3_open_file_str
        call print_string

        call _GetLastError@0

        mov dword [ebp - OF_FILE_STRUCT_SIZE - 20], 3

        jmp .shutdown

.continue_open_file:
    mov [ebp - OF_FILE_STRUCT_SIZE - 4], eax        ; file handle

    mov edx, ebp
    sub edx, OF_FILE_STRUCT_SIZE + 8
    push edx

    push dword [ebp - OF_FILE_STRUCT_SIZE - 4]
    call _GetFileSize@8                             ; file size in eax

    cmp eax, INVALID_FILE_SIZE
    jne .continue_get_file_size
        push ret_val_4_get_file_size_str.len
        push ret_val_4_get_file_size_str
        call print_string

        call _GetLastError@0

        mov dword [ebp - OF_FILE_STRUCT_SIZE - 20], 4

        jmp .shutdown

.continue_get_file_size:
    mov [ebp - OF_FILE_STRUCT_SIZE - 12], eax       ; file size saved

    mov edx, PAGE_READWRITE
    push edx

    mov edx, MEM_RESERVE
    or edx, MEM_COMMIT
    push edx

    push dword [ebp - OF_FILE_STRUCT_SIZE - 12]     ; file size
    push 0
    call _VirtualAlloc@16

    cmp eax, 0                                      ; if addr is 0
    jne .continue_virtual_alloc
        push ret_val_5_virtual_alloc_str.len
        push ret_val_5_virtual_alloc_str
        call print_string
        
        call _GetLastError@0

        mov dword [ebp - OF_FILE_STRUCT_SIZE - 20], 5

        jmp .shutdown

.continue_virtual_alloc:
    mov dword [ebp - OF_FILE_STRUCT_SIZE - 16], eax ; alloced mem saved

    push 0
    push 0
    push dword [ebp - OF_FILE_STRUCT_SIZE - 12]     ; file size
    push dword [ebp - OF_FILE_STRUCT_SIZE - 16]     ; alloced mem
    push dword [ebp - OF_FILE_STRUCT_SIZE - 4]      ; file handle
    call _ReadFile@20

    cmp eax, 0                                      ; 1: successful read
    jne .continue_read_file
        push ret_val_6_read_file_str.len
        push ret_val_6_read_file_str
        call print_string

        call _GetLastError@0

        mov dword [ebp - OF_FILE_STRUCT_SIZE - 20], 6

        jmp .shutdown

.continue_read_file:
    mov edx, [ebp + 12]                             ; argv
    add edx, 8                                      ; command line Options
    push edx
    push dword [ebp - OF_FILE_STRUCT_SIZE - 16]     ; alloced mem
    call parse_pe

.shutdown:
    push MEM_RELEASE
    push 0
    push dword [ebp - OF_FILE_STRUCT_SIZE - 16]     ; alloced mem
    call _VirtualFree@12

    push dword [ebp - OF_FILE_STRUCT_SIZE - 4]      ; file handle
    call _CloseHandle@4

    add esp, OF_FILE_STRUCT_SIZE + 20               ; free local variable space    
    add esp, 8                                      ; free arg stack

    mov eax, [ebp - OF_FILE_STRUCT_SIZE - 20]       ; return code

    leave
    ret


section .data
%include 'utils_inc_data_32.asm'

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
NT_FILE_HEADER_BUFFER_SIZE equ 20
OPTIONAL_HEADER_BUFFER_SIZE equ 240 ; 224 bytes 32bit / 240 bytes 64bit

; Virtual Alloc
MEM_COMMIT equ 0x00001000
MEM_RESERVE equ 0x00002000

PAGE_READWRITE equ 0x04
PAGE_EXECUTE_READWRITE equ 0x40

; Virtual Free
MEM_RELEASE equ 0x00008000