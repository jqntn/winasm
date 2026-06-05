; ============================================================================
;  hello.asm  --  ultra-minimal x64 "Hello, World!" as a hand-built Windows PE
; ----------------------------------------------------------------------------
;  Build (NASM is the ENTIRE toolchain -- no linker, no libc, no installs):
;
;      nasm -f bin -o hello.exe hello.asm
;
;  `-f bin` writes the file as a flat stream from offset 0, so every label's
;  numeric value equals its file offset. We hand-craft a complete, valid PE32+
;  executable, translating file offsets into image RVAs with the RVA() macro.
;  All code uses RIP-relative addressing, so the image needs NO base-relocation
;  table -- which is why ASLR is left off and it loads at its preferred base.
; ============================================================================

bits 64
default rel

IMAGE_BASE   equ 0x140000000      ; conventional x64 image base
SECT_RVA     equ 0x1000           ; the single section is mapped at this RVA
SECT_FOFF    equ 0x200            ; ...and its raw bytes live here in the file

; Translate a label's file offset into its in-memory RVA. Valid for any label
; located inside the section body (file offset >= SECT_FOFF).
%define RVA(x) ((x) - SECT_FOFF + SECT_RVA)

; Zero-pad the current position up to a multiple of n (explicit, so we never
; depend on the ALIGN macro's padding choice under -f bin).
%macro balign 1
    times ((%1) - (($ - $$) % (%1))) % (%1) db 0
%endmacro

; ============================================================================
;  DOS header (64 bytes) -- only "MZ" + e_lfanew matter; no DOS stub.
; ============================================================================
dos_header:
    db 'MZ'                                   ; e_magic
    times 0x3C - ($ - dos_header) db 0        ; pad up to the e_lfanew field
    dd  pe_signature                          ; e_lfanew -> PE header (= 0x40)

; ============================================================================
;  PE signature + COFF file header (24 bytes)
; ============================================================================
pe_signature:
    db 'PE', 0, 0                             ; "PE\0\0"

coff_header:
    dw 0x8664                                 ; Machine = IMAGE_FILE_MACHINE_AMD64
    dw 1                                      ; NumberOfSections
    dd 0                                      ; TimeDateStamp
    dd 0                                      ; PointerToSymbolTable
    dd 0                                      ; NumberOfSymbols
    dw opt_header_end - opt_header            ; SizeOfOptionalHeader (= 240)
    dw 0x0023                                 ; Characteristics:
                                              ;   RELOCS_STRIPPED(0x1)
                                              ;   | EXECUTABLE_IMAGE(0x2)
                                              ;   | LARGE_ADDRESS_AWARE(0x20)

; ============================================================================
;  Optional header (PE32+) -- 240 bytes including 16 data directories
; ============================================================================
opt_header:
    dw 0x020B                                 ; Magic = PE32+
    db 0                                      ; MajorLinkerVersion
    db 0                                      ; MinorLinkerVersion
    dd code_raw_size                          ; SizeOfCode
    dd 0                                      ; SizeOfInitializedData
    dd 0                                      ; SizeOfUninitializedData
    dd RVA(_start)                            ; AddressOfEntryPoint
    dd SECT_RVA                               ; BaseOfCode
    dq IMAGE_BASE                             ; ImageBase
    dd 0x1000                                 ; SectionAlignment
    dd 0x200                                  ; FileAlignment
    dw 6                                      ; MajorOperatingSystemVersion
    dw 0                                      ; MinorOperatingSystemVersion
    dw 0                                      ; MajorImageVersion
    dw 0                                      ; MinorImageVersion
    dw 6                                      ; MajorSubsystemVersion
    dw 0                                      ; MinorSubsystemVersion
    dd 0                                      ; Win32VersionValue
    dd 0x2000                                 ; SizeOfImage (headers page + 1 section)
    dd 0x200                                  ; SizeOfHeaders
    dd 0                                      ; CheckSum (0 = not verified for EXEs)
    dw 3                                      ; Subsystem = WINDOWS_CUI (console)
    dw 0                                      ; DllCharacteristics (no ASLR/NX)
    dq 0x100000                               ; SizeOfStackReserve
    dq 0x1000                                 ; SizeOfStackCommit
    dq 0x100000                               ; SizeOfHeapReserve
    dq 0x1000                                 ; SizeOfHeapCommit
    dd 0                                      ; LoaderFlags
    dd 16                                     ; NumberOfRvaAndSizes
    ; ---- Data directories (16 x {RVA, Size}) ----
    dd 0, 0                                   ;  0 Export
    dd RVA(import_descriptors), import_dir_size ;  1 Import
    dd 0, 0                                   ;  2 Resource
    dd 0, 0                                   ;  3 Exception
    dd 0, 0                                   ;  4 Certificate
    dd 0, 0                                   ;  5 Base Relocation
    dd 0, 0                                   ;  6 Debug
    dd 0, 0                                   ;  7 Architecture
    dd 0, 0                                   ;  8 Global Ptr
    dd 0, 0                                   ;  9 TLS
    dd 0, 0                                   ; 10 Load Config
    dd 0, 0                                   ; 11 Bound Import
    dd 0, 0                                   ; 12 IAT
    dd 0, 0                                   ; 13 Delay Import
    dd 0, 0                                   ; 14 CLR Runtime
    dd 0, 0                                   ; 15 Reserved
opt_header_end:

; ============================================================================
;  Section header (40 bytes) -- one RWX section, ".text"
; ============================================================================
section_header:
    db '.text', 0, 0, 0                       ; Name (8 bytes)
    dd code_virt_size                         ; VirtualSize
    dd SECT_RVA                               ; VirtualAddress
    dd code_raw_size                          ; SizeOfRawData
    dd SECT_FOFF                              ; PointerToRawData
    dd 0                                      ; PointerToRelocations
    dd 0                                      ; PointerToLinenumbers
    dw 0                                      ; NumberOfRelocations
    dw 0                                      ; NumberOfLinenumbers
    dd 0xE0000060                             ; Characteristics:
                                              ;   CODE(0x20) | INITIALIZED_DATA(0x40)
                                              ;   | EXECUTE | READ | WRITE

; ---- pad all headers out to FileAlignment (0x200) ----
    times SECT_FOFF - ($ - dos_header) db 0

; ============================================================================
;  Section body  (file offset 0x200, RVA 0x1000)
; ============================================================================
section_body:
_start:
    sub     rsp, 0x28                         ; 32B shadow space + 5th-arg slot; aligns RSP to 16
    ; hConsole = GetStdHandle(STD_OUTPUT_HANDLE = -11)
    mov     ecx, -11
    call    [rel iat_GetStdHandle]
    ; WriteFile(hConsole, message, msg_len, &bytes_written, NULL)
    mov     rcx, rax
    lea     rdx, [rel message]
    mov     r8d, msg_len
    lea     r9,  [rel bytes_written]
    mov     qword [rsp + 0x20], 0             ; lpOverlapped = NULL (5th arg, on stack)
    call    [rel iat_WriteFile]
    ; ExitProcess(0)
    xor     ecx, ecx
    call    [rel iat_ExitProcess]
    ; (never returns)

message:
    db  "Hello, World!", 0x0D, 0x0A
msg_len equ $ - message

bytes_written:
    dd  0

; ---- Import Directory Table: one descriptor for kernel32.dll + null term. ----
    balign 4
import_descriptors:
    dd RVA(ilt)                               ; OriginalFirstThunk -> ILT
    dd 0                                      ; TimeDateStamp
    dd 0                                      ; ForwarderChain
    dd RVA(dll_name)                          ; Name -> "kernel32.dll"
    dd RVA(iat)                               ; FirstThunk -> IAT
    dd 0, 0, 0, 0, 0                          ; null terminator descriptor
import_dir_size equ $ - import_descriptors

; ---- Import Lookup Table: names what we import (QWORD entries, by name) ----
    balign 8
ilt:
    dq RVA(name_getstdhandle)
    dq RVA(name_writefile)
    dq RVA(name_exitprocess)
    dq 0                                      ; null terminator

; ---- Import Address Table: loader overwrites these with real pointers ----
iat:
iat_GetStdHandle: dq RVA(name_getstdhandle)
iat_WriteFile:    dq RVA(name_writefile)
iat_ExitProcess:  dq RVA(name_exitprocess)
                  dq 0                        ; null terminator

; ---- Hint/Name entries: WORD hint (0) + ASCII name + NUL, word-aligned ----
    balign 2
name_getstdhandle:
    dw 0
    db "GetStdHandle", 0
    balign 2
name_writefile:
    dw 0
    db "WriteFile", 0
    balign 2
name_exitprocess:
    dw 0
    db "ExitProcess", 0

; ---- Imported DLL name ----
    balign 2
dll_name:
    db "kernel32.dll", 0

section_body_end:
code_virt_size equ section_body_end - section_body

; ---- pad section raw data up to FileAlignment (0x200) ----
    balign 0x200
code_raw_size  equ $ - section_body
