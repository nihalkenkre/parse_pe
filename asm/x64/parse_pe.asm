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

; arg0: ptr to dos header       rcx
; arg1: ptr to sprintf buffer   rdx
; arg2: std handle              r8
print_dos_header:
        push rbp
        mov rbp, rsp

        mov [rbp + 16], rcx             ; ptr to dos header
        mov [rbp + 24], rdx             ; ptr to sprintf buffer
        mov [rbp + 32], r8              ; std handle

        ; rbp - 8 = return value
        ; rbp - 16 = 8 bytes padding
        sub rsp, 16                     ; allocate local variable space
        sub rsp, 32                     ; allocate shadow space
        mov qword [rbp - 8], 0          ; return value

        sub rsp, 272
        mov rcx, [rbp + 24]             ; ptr to sprintf buffer
        mov rdx, dos_header_str
        mov rax, [rbp + 16]             ; ptr to dos header
        movzx r8d, word [rax]
        movzx r9d, word [rax + 2]
        mov r10w, [rax + 4]
        mov [rsp + 32], r10
        mov r10w, [rax + 6]
        mov [rsp + 40], r10
        mov r10w, [rax + 8]
        mov [rsp + 48], r10
        mov r10w, [rax + 10]
        mov [rsp + 56], r10
        mov r10w, [rax + 12]
        mov [rsp + 64], r10
        mov r10w, [rax + 14]
        mov [rsp + 72], r10
        mov r10w, [rax + 16]
        mov [rsp + 80], r10
        mov r10w, [rax + 18]
        mov [rsp + 88], r10
        mov r10w, [rax + 20]
        mov [rsp + 96], r10
        mov r10w, [rax + 22]
        mov [rsp + 104], r10
        mov r10w, [rax + 24]
        mov [rsp + 112], r10
        mov r10w, [rax + 26]
        mov [rsp + 120], r10
        mov r10w, [rax + 28]
        mov [rsp + 128], r10
        mov r10w, [rax + 30]
        mov [rsp + 136], r10
        mov r10w, [rax + 32]
        mov [rsp + 144], r10
        mov r10w, [rax + 34]
        mov [rsp + 152], r10
        mov r10w, [rax + 36]
        mov [rsp + 160], r10
        mov r10w, [rax + 38]
        mov [rsp + 168], r10
        mov r10w, [rax + 40]
        mov [rsp + 176], r10
        mov r10w, [rax + 42]
        mov [rsp + 184], r10
        mov r10w, [rax + 44]
        mov [rsp + 192], r10
        mov r10w, [rax + 46]
        mov [rsp + 200], r10
        mov r10w, [rax + 48]
        mov [rsp + 208], r10
        mov r10w, [rax + 50]
        mov [rsp + 216], r10
        mov r10w, [rax + 52]
        mov [rsp + 224], r10
        mov r10w, [rax + 54]
        mov [rsp + 232], r10
        mov r10w, [rax + 56]
        mov [rsp + 240], r10
        mov r10w, [rax + 58]
        mov [rsp + 248], r10
        mov r10w, [rax + 60]
        mov [rsp + 256], r10
        mov r10w, [rax + 62]
        mov [rsp + 264], r10
        mov r10w, [rax + 64]
        mov [rsp + 272], r10
        call sprintf
        add rsp, 272

        mov rcx, [rbp + 24]             ; ptr to sprintf buffer
        call strlen

        mov rcx, [rbp + 32]             ; std handle
        mov rdx, [rbp + 24]             ; ptr to sprintf buffer
        mov r8, rax                     ; strlen
        call print_string

    .shutdown:
        mov rax, [rbp - 8]              ; return value

        leave
        ret

; arg0: ptr to nt headers       rcx
; arg1: ptr to sprintf buffer   rdx
; arg2: std handle              r8
print_nt_headers_signature:
        push rbp
        mov rbp, rsp

        mov [rbp + 16], rcx                 ; ptr to nt headers
        mov [rbp + 24], rdx                 ; ptr to sprintf buffer
        mov [rbp + 32], r8                  ; std handle

        ; rbp - 8 = return value
        ; rbp - 16 = 8 bytes padding
        sub rsp, 16                         ; allocate local variable space
        sub rsp, 32                         ; allocate shadow space

        mov qword [rbp - 8], 0              ; return value

        mov rcx, [rbp + 24]                 ; ptr to sprintf buffer
        mov rdx, nt_headers_signature_str
        mov rax, [rbp + 16]                 ; ptr to nt headers
        mov r8d, [rax]
        call sprintf

        mov rcx, [ebp + 24]                 ; ptr to sprintf buffer
        call strlen

        mov rcx, [rbp + 32]                 ; std handle
        mov rdx, [rbp + 24]                 ; ptr to sprintf buffer
        mov r8, rax                         ; strlen
        call print_string

    .shutdown:
        mov rax, [rbp - 8]                  ; return value

        leave
        ret

; arg0: ptr to nt headers file header   rcx
; arg1: ptr to sprintf buffer           rdx
; arg2: std handle                      r8
print_nt_headers_file_header:
        push rbp
        mov rbp, rsp

        mov [rbp + 16], rcx                 ; ptr to nt headers file header
        mov [rbp + 24], rdx                 ; ptr to sprintf buffer
        mov [rbp + 32], r8                  ; std handle

        ; rbp - 8 = return value
        ; rbp - 16 = 8 bytes padding
        sub rsp, 16                         ; allocate local variable space
        sub rsp, 32                         ; allocate shadow space

        mov qword [rbp - 8], 0              ; return value

        sub rsp, 48                         ; 5 args + 8 byte padding
        mov rcx, [rbp + 24]                 ; ptr to sprintf buffer
        mov rdx, nt_headers_file_header_str

        mov rax, [rbp + 16]                 ; ptr to nt headers file header
        mov r8w, [rax]
        mov r9w, [rax + 2]
        mov r10d, [rax + 4]
        mov [rsp + 32], r10
        mov r10d, [rax + 8]
        mov [rsp + 40], r10
        mov r10d, [rax + 12]
        mov [rsp + 48], r10
        mov r10w, [rax + 16]
        mov [rsp + 56], r10
        mov r10w, [rax + 18]
        mov [rsp + 64], r10
        call sprintf
        add rsp, 48                         ; 5 args + 8 byte padding

        mov rcx, [ebp + 24]                 ; ptr to sprintf buffer
        call strlen

        mov rcx, [rbp + 32]                 ; std handle
        mov rdx, [rbp + 24]                 ; ptr to sprintf buffer
        mov r8, rax                         ; strlen
        call print_string

    .shutdown:
        mov rax, [rbp - 8]                  ; return value

        leave
        ret

; arg0: ptr to nt headers optional header   rcx
; arg1: ptr to sprintf buffer               rdx
; arg2: std handle                          r8
print_nt_headers_optional_header:
        push rbp
        mov rbp, rsp

        mov [rbp + 16], rcx                 ; ptr to nt headers optional header
        mov [rbp + 24], rdx                 ; ptr to sprintf buffer
        mov [rbp + 32], r8                  ; std handle

        ; rbp - 8 = return value
        ; rbp - 16 = 8 bytes padding
        sub rsp, 16                         ; allocate local variable space
        sub rsp, 32                         ; allocate shadow space

        mov qword [rbp - 8], 0              ; return value

        sub rsp, 496
        mov rcx, [rbp + 24]                 ; ptr to sprintf buffer
        mov rax, [rbp + 16]                 ; ptr to nt headers optional header

        cmp word [rax], 0x20b               ; is pe 64 bit ?
        je .64bitOptionalHeader

        ; 32 bit optional header
        mov rdx, nt_headers_optional_header_32_str
        mov r8w, [rax]
        mov r9b, [rax + 2]
        mov r10b, [rax + 3]
        mov [rsp + 32], r10
        mov r10d, [rax + 4]
        mov [rsp + 40], r10
        mov r10d, [rax + 8]
        mov [rsp + 48], r10
        mov r10d, [rax + 12]
        mov [rsp + 56], r10
        mov r10d, [rax + 16]
        mov [rsp + 64], r10
        mov r10d, [rax + 20]
        mov [rsp + 72], r10
        mov r10d, [rax + 24]
        mov [rsp + 80], r10
        mov r10d, [rax + 28]
        mov [rsp + 88], r10
        mov r10d, [rax + 32]
        mov [rsp + 96], r10
        mov r10d, [rax + 36]
        mov [rsp + 104], r10
        mov r10w, [rax + 40]
        mov [rsp + 112], r10
        mov r10w, [rax + 42]
        mov [rsp + 120], r10
        mov r10w, [rax + 44]
        mov [rsp + 128], r10
        mov r10w, [rax + 46]
        mov [rsp + 136], r10
        mov r10w, [rax + 48]
        mov [rsp + 144], r10
        mov r10w, [rax + 50]
        mov [rsp + 152], r10
        mov r10d, [rax + 52]
        mov [rsp + 160], r10
        mov r10d, [rax + 56]
        mov [rsp + 168], r10
        mov r10d, [rax + 60]
        mov [rsp + 176], r10
        mov r10d, [rax + 64]
        mov [rsp + 184], r10
        mov r10w, [rax + 68]
        mov [rsp + 192], r10
        mov r10w, [rax + 70]
        mov [rsp + 200], r10
        mov r10d, [rax + 72]
        mov [rsp + 208], r10
        mov r10d, [rax + 76]
        mov [rsp + 216], r10
        mov r10d, [rax + 80]
        mov [rsp + 224], r10
        mov r10d, [rax + 84]
        mov [rsp + 232], r10
        mov r10d, [rax + 88]
        mov [rsp + 240], r10
        mov r10d, [rax + 92]
        mov [rsp + 248], r10
        mov r10d, [rax + 96]
        mov [rsp + 256], r10
        mov r10d, [rax + 100]
        mov [rsp + 264], r10
        mov r10d, [rax + 104]
        mov [rsp + 272], r10
        mov r10d, [rax + 108]
        mov [rsp + 280], r10
        mov r10d, [rax + 112]
        mov [rsp + 288], r10
        mov r10d, [rax + 116]
        mov [rsp + 296], r10
        mov r10d, [rax + 120]
        mov [rsp + 304], r10
        mov r10d, [rax + 124]
        mov [rsp + 312], r10
        mov r10d, [rax + 128]
        mov [rsp + 320], r10
        mov r10d, [rax + 132]
        mov [rsp + 328], r10
        mov r10d, [rax + 136]
        mov [rsp + 336], r10
        mov r10d, [rax + 140]
        mov [rsp + 344], r10
        mov r10d, [rax + 144]
        mov [rsp + 352], r10
        mov r10d, [rax + 148]
        mov [rsp + 360], r10
        mov r10d, [rax + 152]
        mov [rsp + 368], r10
        mov r10d, [rax + 156]
        mov [rsp + 376], r10
        mov r10d, [rax + 160]
        mov [rsp + 384], r10
        mov r10d, [rax + 164]
        mov [rsp + 392], r10
        mov r10d, [rax + 168]
        mov [rsp + 400], r10
        mov r10d, [rax + 172]
        mov [rsp + 408], r10
        mov r10d, [rax + 176]
        mov [rsp + 416], r10
        mov r10d, [rax + 180]
        mov [rsp + 424], r10
        mov r10d, [rax + 184]
        mov [rsp + 432], r10
        mov r10d, [rax + 188]
        mov [rsp + 440], r10
        mov r10d, [rax + 192]
        mov [rsp + 448], r10
        mov r10d, [rax + 196]
        mov [rsp + 456], r10
        mov r10d, [rax + 200]
        mov [rsp + 464], r10
        mov r10d, [rax + 204]
        mov [rsp + 472], r10
        mov r10d, [rax + 208]
        mov [rsp + 480], r10
        mov r10d, [rax + 212]
        mov [rsp + 488], r10
        mov r10d, [rax + 216]
        mov [rsp + 496], r10
        mov r10d, [rax + 220]
        mov [rsp + 504], r10
        mov r10d, [rax + 224]
        mov [rsp + 512], r10

        jmp .continue_after_bit_check

    .64bitOptionalHeader:
        mov rdx, nt_headers_optional_header_64_str
        mov r8w, [rax]
        mov r9b, [rax + 2]
        mov r10b, [rax + 3]
        mov [rsp + 32], r10
        mov r10d, [rax + 4]
        mov [rsp + 40], r10
        mov r10d, [rax + 8]
        mov [rsp + 48], r10
        mov r10d, [rax + 12]
        mov [rsp + 56], r10
        mov r10d, [rax + 16]
        mov [rsp + 64], r10
        mov r10d, [rax + 20]
        mov [rsp + 72], r10
        mov r10, [rax + 24]
        mov [rsp + 80], r10
        mov r10d, [rax + 32]
        mov [rsp + 88], r10
        mov r10d, [rax + 36]
        mov [rsp + 96], r10
        mov r10w, [rax + 40]
        mov [rsp + 104], r10
        mov r10w, [rax + 42]
        mov [rsp + 112], r10
        mov r10w, [rax + 44]
        mov [rsp + 120], r10
        mov r10w, [rax + 46]
        mov [rsp + 128], r10
        mov r10w, [rax + 48]
        mov [rsp + 136], r10
        mov r10w, [rax + 50]
        mov [rsp + 144], r10
        mov r10d, [rax + 52]
        mov [rsp + 152], r10
        mov r10d, [rax + 56]
        mov [rsp + 160], r10
        mov r10d, [rax + 60]
        mov [rsp + 168], r10
        mov r10d, [rax + 64]
        mov [rsp + 176], r10
        mov r10w, [rax + 68]
        mov [rsp + 184], r10
        mov r10w, [rax + 70]
        mov [rsp + 192], r10
        mov r10, [rax + 72]
        mov [rsp + 200], r10
        mov r10, [rax + 80]
        mov [rsp + 208], r10
        mov r10, [rax + 88]
        mov [rsp + 216], r10
        mov r10, [rax + 96]
        mov [rsp + 224], r10
        mov r10d, [rax + 104]
        mov [rsp + 232], r10
        mov r10d, [rax + 108]
        mov [rsp + 240], r10
        mov r10d, [rax + 112]
        mov [rsp + 248], r10
        mov r10d, [rax + 116]
        mov [rsp + 256], r10
        mov r10d, [rax + 120]
        mov [rsp + 264], r10
        mov r10d, [rax + 124]
        mov [rsp + 272], r10
        mov r10d, [rax + 128]
        mov [rsp + 280], r10
        mov r10d, [rax + 132]
        mov [rsp + 288], r10
        mov r10d, [rax + 136]
        mov [rsp + 296], r10
        mov r10d, [rax + 140]
        mov [rsp + 304], r10
        mov r10d, [rax + 144]
        mov [rsp + 312], r10
        mov r10d, [rax + 148]
        mov [rsp + 320], r10
        mov r10d, [rax + 152]
        mov [rsp + 328], r10
        mov r10d, [rax + 156]
        mov [rsp + 336], r10
        mov r10d, [rax + 160]
        mov [rsp + 344], r10
        mov r10d, [rax + 164]
        mov [rsp + 352], r10
        mov r10d, [rax + 168]
        mov [rsp + 360], r10
        mov r10d, [rax + 172]
        mov [rsp + 368], r10
        mov r10d, [rax + 176]
        mov [rsp + 376], r10
        mov r10d, [rax + 180]
        mov [rsp + 384], r10
        mov r10d, [rax + 184]
        mov [rsp + 392], r10
        mov r10d, [rax + 188]
        mov [rsp + 400], r10
        mov r10d, [rax + 192]
        mov [rsp + 408], r10
        mov r10d, [rax + 196]
        mov [rsp + 416], r10
        mov r10d, [rax + 200]
        mov [rsp + 424], r10
        mov r10d, [rax + 204]
        mov [rsp + 432], r10
        mov r10d, [rax + 208]
        mov [rsp + 440], r10
        mov r10d, [rax + 212]
        mov [rsp + 448], r10
        mov r10d, [rax + 216]
        mov [rsp + 456], r10
        mov r10d, [rax + 220]
        mov [rsp + 464], r10
        mov r10d, [rax + 224]
        mov [rsp + 472], r10
        mov r10d, [rax + 228]
        mov [rsp + 480], r10
        mov r10d, [rax + 232]
        mov [rsp + 488], r10
        mov r10d, [rax + 236]
        mov [rsp + 496], r10
        mov r10d, [rax + 240]
        mov [rsp + 504], r10

    .continue_after_bit_check:

        call sprintf
        add rsp, 496

        mov rcx, [ebp + 24]                 ; ptr to sprintf buffer
        call strlen

        mov rcx, [rbp + 32]                 ; std handle
        mov rdx, [rbp + 24]                 ; ptr to sprintf buffer
        mov r8, rax                         ; strlen
        call print_string

    .shutdown:
        mov rax, [rbp - 8]                  ; return value

        leave
        ret

; arg0: ptr to section headers      rcx
; arg1: section header count        rdx
; arg2: sprintf buffer              r8
; arg3: std handle                  r9
print_section_headers:
        push rbp
        mov rbp, rsp
        
        mov [rbp + 16], rcx             ; ptr to section headers
        mov [rbp + 24], rdx             ; section header count
        mov [rbp + 32], r8              ; ptr to sprintf buffer
        mov [rbp + 40], r9              ; std handle

        ; rbp - 8 = return value
        ; rbp - 16 = current section header addr
        ; rbp - 24 = section header index reverse
        ; rbp - 32 = 8 bytes padding
        sub rsp, 16                     ; allocate local variable space
        sub rsp, 32                     ; allocate shadow space
        
        mov qword [rbp - 8], 0          ; return value
        mov rcx, [rbp + 24]             ; section header count
        mov [rbp - 24], rcx             ; section header index reverse 

        mov rax, [rbp + 16]             ; ptr to section headers
        mov [rbp - 16], rax             ; current section header addr

    .loop:
        mov rax, [rbp - 16]             ; current section header addr

        sub rsp, 80
        mov rcx, [rbp + 32]             ; ptr to sprintf buffer
        mov rdx, section_headers_str
        mov r8, rax
        mov r9d, [rax + 8]
        mov r10d, [rax + 12]
        mov [rsp + 32], r10
        mov r10d, [rax + 16]
        mov [rsp + 40], r10
        mov r10d, [rax + 20]
        mov [rsp + 48], r10
        mov r10d, [rax + 24]
        mov [rsp + 56], r10
        mov r10d, [rax + 28]
        mov [rsp + 64], r10
        mov r10w, [rax + 32]
        mov [rsp + 72], r10
        mov r10w, [rax + 34]
        mov [rsp + 80], r10
        mov r10d, [rax + 36]
        mov [rsp + 88], r10
        mov r10d, [rax + 40]
        mov [rsp + 96], r10
        call sprintf
        add rsp, 80

        mov rcx, [rbp + 32]             ; ptr to sprintf buffer
        call strlen

        mov rcx, [rbp + 40]             ; std handle
        mov rdx, [rbp + 32]             ; ptr to sprintf buffer
        mov r8, rax                     ; strlen
        call print_string

        add qword [rbp - 16], 40        ; current section header addr
        dec qword [rbp - 24]            ; section header index reverse

        jnz .loop

    .shutdown:
        mov rax, [rbp - 8]              ; return value

        leave
        ret

; arg0: base addr file contents     rcx
; arg1: Options                     rdx
; arg2: std handle                  r8
parse_pe:
        push rbp
        mov rbp, rsp

        mov [rbp + 16], rcx             ; base addr
        mov [rbp + 24], rdx             ; options
        mov [rbp + 32], r8              ; std handle

        ; rbp - 8 = return value
        ; rbp - 16 = nt header
        ; rbp - 24 = file header
        ; rbp - 32 = optional header
        ; rbp - 40 = section header count
        ; rbp - 48 = section headers
        ; rbp - 56 = file bitness 1: 64 bit, 0: 32 bit
        ; rbp - 64 = rbx
        ; rbp - 72 = options enum;  1 = dos header, 2 = dos stub, 3 = signature
        ;                           4 = file header, 5 = optional header, 6 = section header
        ;                           7 = export functions, 8 = import functions
        ; rbp - 8264 = 8192 byte buffer for sprintf
        ; rbp - 8272 = 8 byte padding
        sub rsp, 8272                                   ; allocate local variable space
        sub rsp, 32                                     ; allocate shadow space

        mov qword [rbp - 8], 0                          ; return value
        mov [rbp - 64], rbx                             ; save rbx

        mov rcx, dos_header_arg
        mov rdx, [rbp + 24]                             ; Options
        call strcmpAA
        cmp rax, 0
        je .cmp_dos_stub

        mov qword [rbp - 72], 1                         ; dos header enum
        jmp .cmp_end

    .cmp_dos_stub:
        mov rcx, dos_stub_arg
        mov rdx, [rbp + 24]                             ; Options
        call strcmpAA
        cmp rax, 0
        je .cmp_nt_headers_signature

        mov qword [rbp - 72], 2                         ; dos stub enum
        jmp .cmp_end

    .cmp_nt_headers_signature:
        mov rcx, nt_headers_signature_arg
        mov rdx, [rbp + 24]                             ; Options
        call strcmpAA
        cmp rax, 0
        je .cmp_nt_headers_file_header

        mov qword [rbp - 72], 3                         ; nt headers signature enum
        jmp .cmp_end

    .cmp_nt_headers_file_header:
        mov rcx, nt_headers_file_header_arg
        mov rdx, [rbp + 24]                             ; Options
        call strcmpAA
        cmp rax, 0
        je .cmp_nt_headers_optional_header

        mov qword [rbp - 72], 4                         ; nt headers file header enum
        jmp .cmp_end

    .cmp_nt_headers_optional_header:
        mov rcx, nt_headers_optional_header_arg
        mov rdx, [rbp + 24]                             ; Options
        call strcmpAA
        cmp rax, 0
        je .cmp_section_headers

        mov qword [rbp - 72], 5                         ; nt headers optional header enum
        jmp .cmp_end
    
    .cmp_section_headers:
        mov rcx, section_headers_arg
        mov rdx, [rbp + 24]                             ; Options
        call strcmpAA
        cmp rax, 0
        je .cmp_exported_functions

        mov qword [rbp - 72], 6                         ; section headers enum
        jmp .cmp_end
    
    .cmp_exported_functions:
        mov rcx, exported_functions_arg
        mov rdx, [rbp + 24]                             ; Options
        call strcmpAA
        cmp rax, 0
        je .cmp_imported_functions

        mov qword [rbp - 72], 6                         ; exported functions enum
        jmp .cmp_end
 
    .cmp_imported_functions:
        mov rcx, imported_functions_arg
        mov rdx, [rbp + 24]                             ; Options
        call strcmpAA
        cmp rax, 0
        je .options_arg_err

        mov qword [rbp - 72], 6                         ; exported functions enum
        jmp .cmp_end
    
    .options_arg_err:
        mov rcx, [rbp + 32]                             ; std handle
        mov rdx, ret_val_1_str
        mov r8, ret_val_1_str.len
        call print_string

        jmp .shutdown

    .cmp_end:
        ; retrive and  save the information to the above stack variables
        mov rbx, [rbp + 16]                             ; base addr
        cmp qword [rbp - 72], 1                         ; print dos header
        jne .continue_from_print_dos_header_check

        ; print dos header
        mov rcx, [rbp + 16]                             ; base addr
        mov rdx, rbp
        sub rdx, 8264                                   ; sprintf buffer
        mov r8, [rbp + 32]                              ; std handle
        call print_dos_header

    .continue_from_print_dos_header_check:

        add rbx, 0x3c                                   ; offset of e_lfanew
        movzx eax, word [rbx]                           ; e_lfanew in rax

        cmp qword [ebp - 72], 2                         ; print dos stub
        jne .continue_from_print_dos_stub_check

        ; print dos stub

    .continue_from_print_dos_stub_check:

        mov rbx, [rbp + 16]                             ; base addr
        add rbx, rax                                    ; nt headers
        mov [rbp - 16], rbx                             ; nt headers saved

        cmp qword [ebp - 72], 3                         ; print nt headers signature
        jne .continue_from_nt_headers_signature_check

        ; print nt header signature
        mov rcx, [rbp - 16]                             ; nt headers
        mov rdx, rbp
        sub rdx, 8264                                   ; sprintf buffer
        mov r8, [rbp + 32]                              ; std handle
        call print_nt_headers_signature
       
    .continue_from_nt_headers_signature_check:
        add rbx, 4                                      ; file header
        mov [rbp - 24], rbx                             ; file header saved

        cmp qword [ebp - 72], 4                         ; print nt headers file header
        jne .continue_from_nt_headers_file_header_check

        ; print nt headers file header
        mov rcx, [rbp - 24]                             ; file header
        mov rdx, rbp
        sub rdx, 8264                                   ; sprintf buffer
        mov r8, [rbp + 32]                              ; std handle
        call print_nt_headers_file_header
       
    .continue_from_nt_headers_file_header_check:

        add rbx, 20                                     ; optional header
        mov [rbp - 32], rbx                             ; optional header saved

        cmp qword [rbp - 72], 5                         ; print nt headers optional header
        jne .continue_from_nt_headers_optional_header_check

        ; print nt headers optional header
        mov rcx, [rbp - 32]                             ; optional header
        mov rdx, rbp
        sub rdx, 8264                                   ; sprintf buffer
        mov r8, [rbp + 32]                              ; std handle
        call print_nt_headers_optional_header

    .continue_from_nt_headers_optional_header_check:
        mov rbx, [rbp - 24]                             ; file header
        add rbx, 2                                      ; section header count
        movzx eax, word [rbx]
        mov [rbp - 40], rax                             ; section header count

        mov rax, [rbp - 24]                             ; file header
        mov ax, word [rax]

        cmp word ax, 0x14c                              ; is file 32 bit
        je .32bit
            mov rax, [rbp - 32]                         ; optional header
            add rax, 240                                ; end of optional header, start of section headers

            mov [rbp - 48], rax                         ; section headers
            mov qword [rbp - 56], 1                     ; file bitness saved 1 for 64 bit

        jmp .continue_bit_check

    .32bit:
        mov rax, [rbp - 32]                             ; optional header in rax
        add rax, 224                                    ; end of optional header, start for section headers

        mov [rbp - 48], rax                             ; section headers
        mov qword [rbp - 56], 0                         ; file bitness saved, 0 for 32 bit

    .continue_bit_check:
        cmp qword [rbp - 72], 6                         ; print section headers
        jne .continue_from_section_header_check

        ; print section headers
        mov rcx, [rbp - 48]                             ; section headers
        mov rdx, [rbp - 40]                             ; section header count
        mov r8, rbp
        sub r8, 8264                                    ; sprintf buffer
        mov r9, [rbp + 32]                              ; std handle
        call print_section_headers

    .continue_from_section_header_check:

    .iat:    
        ; loop IDT
        mov rax, [rbp - 32]                             ; optional header

        cmp qword [rbp - 56], 0                         ; is file 32 bit
        je .32bitidt
            add rax, 120                                ; IDT
            mov eax, [eax]

            cmp eax, 0                                  ; if IDT rva == 0 ?
            je .edt

            jmp .continue_bitcheck_idt

    .32bitidt:
        add rax, 104                                    ; IDT
        mov eax, [eax]

        cmp eax, 0                                      ; if IDT rva == 0 ?
        je .edt

    .continue_bitcheck_idt:
        mov ecx, eax                                    ; rva
        mov rdx, [rbp - 48]                             ; section headers
        mov r8, [rbp - 40]                              ; section header count
        mov r9, [rbp + 16]                              ; file contents base addr
        call loop_import_descriptor_table

    .edt:
        ; loop EDT
        mov rax, [rbp - 32]                             ; optional header
        cmp qword [rbp - 56], 0                         ; is file 32 bit

        je .32bitedt
            add rax, 112                                ; EDT
            mov eax, [eax]

            cmp eax, 0                                  ; if EDT rva == 0 ?
            je .shutdown

            jmp .continue_bitcheck_edt

    .32bitedt:
        add rax, 96                                     ; EDT
        mov eax, [eax]

        cmp eax, 0                                      ; if EDT rva == 0 ?
        je .shutdown

    .continue_bitcheck_edt:
        mov ecx, eax                                    ; rva
        mov rdx, [rbp - 48]                             ; section headers
        mov r8, [rbp - 40]                              ; section header count
        mov r9, [rbp + 16]                              ; file contents base addr
        call loop_export_descriptor_table

    .shutdown:

        mov rbx, [rbp - 64]                             ; restore rbx
        mov rax, [rbp - 8]                              ; return value

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
        sub rsp, 208                                    ; allocate local variable space
        sub rsp, 32                                     ; allocate shadow space

        mov qword [rbp - 8], 0                          ; return value

        call get_kernel_module_handle
        mov [rbp - 192], rax                            ; kernel handle

        mov rcx, [rbp - 192]                            ; kernel handle
        call populate_kernel_function_ptrs_by_name

        mov rcx, STD_HANDLE_ENUM
        call [get_std_handle]

        mov [rbp - 200], rax                            ; std handle
   
        ; check if 2 args are passed to the exe
        cmp byte [rbp + 16], 3                          ; argc == 3 ?
        je .continue_argc_check

        mov rcx, [rbp - 200]                            ; std handle
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
        mov [rbp - 208], rax                            ; shlwapi addr

        mov rcx, path_file_exists_a_xor
        mov rdx, path_file_exists_a_xor.len
        mov r8, xor_key
        mov r9, xor_key.len
        call my_xor

        mov rcx, [rbp - 208]                            ; shlwapi addr
        mov rdx, path_file_exists_a_xor
        call [get_proc_address]

        cmp rax, 0
        je .shutdown

        mov [path_file_exists_a], rax

        mov rcx, [rbp + 24]                             ; argv in rcx
        mov rcx, [rcx + 8]                              ; argv[1] in rcx
        call [path_file_exists_a]

        cmp eax, 1                                      ; does file exist
        je .continue_path_file_check
            mov rcx, [rbp - 200]                        ; std handle
            mov rdx, ret_val_2_str
            mov r8, ret_val_2_str.len
            call print_string

            call [get_last_error]

            mov qword [rbp - 8], 2

            jmp .shutdown

    .continue_path_file_check:

        mov rdx, [rbp + 24]                             ; argv in rdx
        add rdx, 8                                      ; command line FileName in rdx
        mov rcx, [rdx]

        mov rdx, rsp
        sub rdx, 152                                    ; addr of struct in rdx
        xor r8, r8

        call [open_file]                                ; file handle in rax

        cmp rax, INVALID_HANDLE_VALUE
        jne .continue_open_file
            mov rcx, [rbp - 200]                        ; std handle
            mov rdx, ret_val_3_open_file_str
            mov r8, ret_val_3_open_file_str.len
            call print_string

            call [get_last_error]

            mov qword [rbp - 8], 3

            jmp .shutdown

    .continue_open_file:
        mov qword [rbp - 160], rax                      ; file handle saved
        
        mov rcx, [rbp - 160]                            ; file handle
        mov rdx, rbp
        sub rdx, 168                                    ; file size high
        call [get_file_size]                            ; file size in rax

        cmp rax, INVALID_FILE_SIZE
        jne .continue_get_file_size
            mov rcx, [rbp - 200]                        ; std handle
            mov rdx, ret_val_4_get_file_size_str
            mov r8, ret_val_4_get_file_size_str.len
            call print_string

            call [get_last_error]

            mov qword [rbp - 8], 4

            jmp .shutdown

    .continue_get_file_size:
        mov qword [rbp - 176], rax                      ; file size saved

        xor rcx, rcx
        mov rdx, [rbp - 176]                            ; dw file size
        mov r8, MEM_COMMIT
        or r8, MEM_RESERVE
        mov r9, PAGE_READWRITE
        call [virtual_alloc]                            ; allocated addr in rax

        cmp rax, 0                                      ; if addr == NULL
        jne .continue_virtual_alloc
            mov rcx, [rbp - 200]                        ; std handle
            mov rdx, ret_val_5_virtual_alloc_str
            mov r8, ret_val_5_virtual_alloc_str.len
            call print_string

            call [get_last_error]

            mov qword [rbp - 8], 5

            jmp .shutdown

    .continue_virtual_alloc:
        mov qword [rbp - 184], rax                      ; alloc addr saved

        sub rsp, 16                                     ; 1 arg + 8 byte padding
        mov rcx, [rbp - 160]                            ; file handle
        mov rdx, [rbp - 184]                            ; ptr to allocated mem
        mov r8, [rbp - 176]                             ; n Bytes to read
        xor r9, r9
        mov qword [rsp + 32], 0
        call [read_file]
        add rsp, 16                                     ; 1 arg + 8 byte padding

        cmp rax, 1                                      ; 1: successful read
        je .continue_read_file
            mov rcx, [rbp - 200]                        ; std handle
            mov rdx, ret_val_6_read_file_str
            mov r8, ret_val_6_read_file_str.len
            call print_string

            call [get_last_error]

            mov qword [rbp - 8], 6

            jmp .shutdown

    .continue_read_file:
        
        mov rcx, [rbp - 184]                            ; base addr of file
        mov rdx, [rbp + 24]                             ; argv in rdx
        add rdx, 16                                     ; command line Options in rdx
        mov rdx, [rdx]
        mov r8, [rbp - 200]                             ; std handle
        call parse_pe

    .shutdown:
        mov rcx, [rbp - 184]                            ; ptr to file contents
        xor rdx, rdx 
        mov r8, MEM_RELEASE
        call [virtual_free]

        mov rcx, [rbp - 160]                            ; file handle
        call [close_handle]

        mov rax, [rbp - 8]                              ; return code

        leave
        ret

section .data
%include '../utils/utils_64_data.asm'

ret_val_1_str: db 'Usage: parse_pe.exe <filename> <options>', 0xa, ' <options>: --dos-header', 0xa, '            --dos-stub', 0xa, '            --nt-headers-signature', 0xa,'            --nt-headers-file-header', 0xa, '            --nt-headers-optional-header', 0xa, '            --section-headers', 0xa, '            --imported-functions', 0xa, '            --exported-functions', 0
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

nt_headers_signature_arg: db '--nt-headers-signature', 0
.len equ $ - nt_headers_signature_arg

nt_headers_file_header_arg: db '--nt-headers-file-header', 0
.len equ $ - nt_headers_file_header_arg

nt_headers_optional_header_arg: db '--nt-headers-optional-header', 0
.len equ $ - nt_headers_optional_header_arg

section_headers_arg: db '--section-headers', 0
.len equ $ - section_headers_arg

imported_functions_arg: db '--imported-functions', 0
.len equ $ - imported_functions_arg

exported_functions_arg: db '--exported-functions', 0
.len equ $ - exported_functions_arg

shlwapi_xor: db 0x63, 0x58, 0x5c, 0x47, 0x51, 0x40, 0x59, 0x1e, 0x54, 0x5c, 0x5c, 0
.len equ $ - shlwapi_xor - 1

path_file_exists_a_xor: db 0x60, 0x51, 0x44, 0x58, 0x76, 0x59, 0x5c, 0x55, 0x75, 0x48, 0x59, 0x43, 0x44, 0x43, 0x71, 0
.len equ $ - path_file_exists_a_xor - 1

dos_header_str: db '                DOS Header', 0xa, \
                'Magic Number                   : %xw', 0xa, \
                'Bytes on Last Page             : 0x%xw', 0xa, \
                'Pages in file                  : 0x%xw', 0xa, \
                'Relocations                    : 0x%xw', 0xa, \
                'Paragaph Header Size           : 0x%xw', 0xa, \
                'Min. extra paragaphs           : 0x%xw', 0xa, \
                'Max. extra paragaphs           : 0x%xw', 0xa, \
                'Initial Relative SS value      : 0x%xw', 0xa, \
                'Initial SP value               : 0x%xw', 0xa, \
                'Checksum                       : 0x%xw', 0xa, \
                'Initial IP value               : 0x%xw', 0xa, \
                'Initial Relative CS value      : 0x%xw', 0xa, \
                'File Addr of Reloc table       : 0x%xw', 0xa, \
                'Overlay Number                 : 0x%xw', 0xa, \
                'Reserved Words                 : 0x%xw 0x%xw 0x%xw 0x%xw', 0xa, \
                'OEM Identifier                 : 0x%xw', 0xa, \
                'OEM Information                : 0x%xw', 0xa, \
                'Reserved Words                 : 0x%xw 0x%xw 0x%xw 0x%xw 0x%xw 0x%xw 0x%xw 0x%xw 0x%xw 0x%xw', 0xa, \
                'File Addr of New EXE header    : 0x%xd', 0
.len equ $ - dos_header_str

dos_stub_str: db '', 0

nt_headers_signature_str: db '      NT headers Signature', 0xa, \
                            'Signature: 0x%xd', 0
.len equ $ - nt_headers_signature_str

nt_headers_file_header_str: db '        NT headers File Header', 0xa, \
                                'Machine            : 0x%xw', 0xa, \
                                'Section Count      : 0x%xw', 0xa, \
                                'Time Date Stamp    : 0x%xd', 0xa, \
                                'Sym Table Ptr      : 0x%xd', 0xa, \
                                'Sym Count          : 0x%xd', 0xa, \
                                'Optional Hdr Size  : 0x%xw', 0xa, \
                                'Characteristics    : 0x%xw', 0
.len equ $ - nt_headers_file_header_str

nt_headers_optional_header_32_str: db '        NT Headers Optional Header', 0xa, \
                                    'Magic                      : 0x%xw', 0xa, \
                                    'Major Linker Version       : 0x%xb', 0xa, \
                                    'Minor Linker Version       : 0x%xb', 0xa, \
                                    'Code Size                  : 0x%xd', 0xa, \
                                    'Initialized Data Size      : 0x%xd', 0xa, \
                                    'Uninitialized Data Size    : 0x%xd', 0xa, \
                                    'Entry Point Addr           : 0x%xd', 0xa, \
                                    'Base of Code               : 0x%xd', 0xa, \
                                    'Base of Data               : 0x%xd', 0xa, \
                                    'Base                       : 0x%xd', 0xa, \
                                    'Section Alignment          : 0x%xd', 0xa, \
                                    'File Alignment             : 0x%xd', 0xa, \
                                    'Major OS Version           : 0x%xw', 0xa, \
                                    'Minor OS Version           : 0x%xw', 0xa, \
                                    'Major Image Version        : 0x%xw', 0xa, \
                                    'Minor Image Version        : 0x%xw', 0xa, \
                                    'Major Subsystem Version    : 0x%xw', 0xa, \
                                    'Minor Subsystem Version    : 0x%xw', 0xa, \
                                    'Win32 Version value        : 0x%xd', 0xa, \
                                    'Size                       : 0x%xd', 0xa, \
                                    'Headers Size               : 0x%xd', 0xa, \
                                    'Checksum                   : 0x%xd', 0xa, \
                                    'Subsystem                  : 0x%xw', 0xa, \
                                    'Dll Characteristics        : 0x%xw', 0xa, \
                                    'Stack Reserve Size         : 0x%xd', 0xa, \
                                    'Stack Commit Size          : 0x%xd', 0xa, \
                                    'Heap Reserve Size          : 0x%xd', 0xa, \
                                    'Heap Commit Size           : 0x%xd', 0xa, \
                                    'Loader Flags               : 0x%xd', 0xa, \
                                    'Number of RVAs and Sizes   : 0x%xd', 0xa, \
                                    'Export Directory           : RVA 0x%xd Size 0x%xd', 0xa, \
                                    'Import Directory           : RVA 0x%xd Size 0x%xd', 0xa, \
                                    'Resource Directory         : RVA 0x%xd Size 0x%xd', 0xa, \
                                    'Exception Directory        : RVA 0x%xd Size 0x%xd', 0xa, \
                                    'Security Directory         : RVA 0x%xd Size 0x%xd', 0xa, \
                                    'Base Relocation Table      : RVA 0x%xd Size 0x%xd', 0xa, \
                                    'Debug Directory            : RVA 0x%xd Size 0x%xd', 0xa, \
                                    'Arch Specific Data         : RVA 0x%xd Size 0x%xd', 0xa, \
                                    'RVA of Global Ptr          : RVA 0x%xd Size 0x%xd', 0xa, \
                                    'TLS Directory              : RVA 0x%xd Size 0x%xd', 0xa, \
                                    'Load Config Directory      : RVA 0x%xd Size 0x%xd', 0xa, \
                                    'Bound Import Directory     : RVA 0x%xd Size 0x%xd', 0xa, \
                                    'Import Address Table       : RVA 0x%xd Size 0x%xd', 0xa, \
                                    'Delay Load Import Descr    : RVA 0x%xd Size 0x%xd', 0xa, \
                                    '.NET Header                : RVA 0x%xd Size 0x%xd', 0
.len equ $ - nt_headers_optional_header_32_str

nt_headers_optional_header_64_str: db '        NT Headers Optional Header', 0xa, \
                                    'Magic                      : 0x%xw', 0xa, \
                                    'Major Linker Version       : 0x%xb', 0xa, \
                                    'Minor Linker Version       : 0x%xb', 0xa, \
                                    'Code Size                  : 0x%xd', 0xa, \
                                    'Initialized Data Size      : 0x%xd', 0xa, \
                                    'Uninitialized Data Size    : 0x%xd', 0xa, \
                                    'Entry Point Addr           : 0x%xd', 0xa, \
                                    'Base of Code               : 0x%xd', 0xa, \
                                    'Base                       : 0x%xq', 0xa, \
                                    'Section Alignment          : 0x%xd', 0xa, \
                                    'File Alignment             : 0x%xd', 0xa, \
                                    'Major OS Version           : 0x%xw', 0xa, \
                                    'Minor OS Version           : 0x%xw', 0xa, \
                                    'Major Image Version        : 0x%xw', 0xa, \
                                    'Minor Image Version        : 0x%xw', 0xa, \
                                    'Major Subsystem Version    : 0x%xw', 0xa, \
                                    'Minor Subsystem Version    : 0x%xw', 0xa, \
                                    'Win32 Version value        : 0x%xd', 0xa, \
                                    'Size                       : 0x%xd', 0xa, \
                                    'Headers Size               : 0x%xd', 0xa, \
                                    'Checksum                   : 0x%xd', 0xa, \
                                    'Subsystem                  : 0x%xw', 0xa, \
                                    'Dll Characteristics        : 0x%xw', 0xa, \
                                    'Stack Reserve Size         : 0x%xq', 0xa, \
                                    'Stack Commit Size          : 0x%xq', 0xa, \
                                    'Heap Reserve Size          : 0x%xq', 0xa, \
                                    'Heap Commit Size           : 0x%xq', 0xa, \
                                    'Loader Flags               : 0x%xd', 0xa, \
                                    'Number of RVAs and Sizes   : 0x%xd', 0xa, \
                                    'Export Directory           : RVA 0x%xd Size 0x%xd', 0xa, \
                                    'Import Directory           : RVA 0x%xd Size 0x%xd', 0xa, \
                                    'Resource Directory         : RVA 0x%xd Size 0x%xd', 0xa, \
                                    'Exception Directory        : RVA 0x%xd Size 0x%xd', 0xa, \
                                    'Security Directory         : RVA 0x%xd Size 0x%xd', 0xa, \
                                    'Base Relocation Table      : RVA 0x%xd Size 0x%xd', 0xa, \
                                    'Debug Directory            : RVA 0x%xd Size 0x%xd', 0xa, \
                                    'Arch Specific Data         : RVA 0x%xd Size 0x%xd', 0xa, \
                                    'RVA of Global Ptr          : RVA 0x%xd Size 0x%xd', 0xa, \
                                    'TLS Directory              : RVA 0x%xd Size 0x%xd', 0xa, \
                                    'Load Config Directory      : RVA 0x%xd Size 0x%xd', 0xa, \
                                    'Bound Import Directory     : RVA 0x%xd Size 0x%xd', 0xa, \
                                    'Import Address Table       : RVA 0x%xd Size 0x%xd', 0xa, \
                                    'Delay Load Import Descr    : RVA 0x%xd Size 0x%xd', 0xa, \
                                    '.NET Header                : RVA 0x%xd Size 0x%xd', 0
.len equ $ - nt_headers_optional_header_64_str

section_headers_str: db '       Section Header', 0xa, \
                        'Name                   : %s', 0xa, \
                        'Virtual Size           : 0x%xd', 0xa, \
                        'Virtual Addr           : 0x%xd', 0xa, \
                        'Raw Data Size          : 0x%xd', 0xa, \
                        'Raw Data Pointer       : 0x%xd', 0xa, \
                        'Reloc Pointer          : 0x%xd', 0xa, \
                        'Line Numbers Pointer   : 0x%xd', 0xa, \
                        'Relocs Count           : 0x%xd', 0xa, \
                        'Line Numbers Count     : 0x%xd', 0xa, \
                        'Characteristics        : 0x%xd', 0xa, 0
.len equ $ - section_headers_str

STD_HANDLE_ENUM equ -11
INVALID_HANDLE_VALUE equ -1
INVALID_FILE_SIZE equ -1

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