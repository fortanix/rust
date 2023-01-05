LFENCE = b'\x0f\xae\xe8'
MFENCE = b'\x0f\xae\xf0'

# mov    %ds,(%rax)
MOV_DS_TO_DEREF_RAX = b'\x8c\x18'

# mov    %ds,(%rbx)
MOV_DS_TO_DEREF_RBX = b'\x8c\x1b'

# mov    %ds,(%rcx)
MOV_DS_TO_DEREF_RCX = b'\x8c\x19'

# mov    %ds,(%rdx)
MOV_DS_TO_DEREF_RDX = b'\x8c\x1a'

# mov    %ds,(%rsi)
MOV_DS_TO_DEREF_RSI = b'\x8c\x1e'

# mov    %ds,(%rdi)
MOV_DS_TO_DEREF_RDI = b'\x8c\x1f'

# mov    %ds,(%r8)
MOV_DS_TO_DEREF_R8 = b'\x41\x8c\x18'

# mov    %ds,(%r9)
MOV_DS_TO_DEREF_R9 = b'\x41\x8c\x19'

# mov    %ds,(%r10)
MOV_DS_TO_DEREF_R10 = b'\x41\x8c\x1a'

# mov    %ds,(%r11)
MOV_DS_TO_DEREF_R11 = b'\x41\x8c\x1b'

# mov    %ds,(%r12)
MOV_DS_TO_DEREF_R12 = b'\x41\x8c\x1c\x24'

# mov    %ds,(%r13)
MOV_DS_TO_DEREF_R13 = b'\x41\x8c\x5d\x00'

# mov    %ds,(%r14)
MOV_DS_TO_DEREF_R14 = b'\x41\x8c\x1e'

# mov    %ds,(%r15)
MOV_DS_TO_DEREF_R15 = b'\x41\x8c\x1f'

# 0f 00 28             	verw   (%rax)
VERW_RAX = b'\x0f\x00\x28'

# 0f 00 2b             	verw   (%rbx)
VERW_RBX = b'\x0f\x00\x2b'

# 0f 00 29             	verw   (%rcx)
VERW_RCX = b'\x0f\x00\x29'

# 0f 00 2a             	verw   (%rdx)
VERW_RDX = b'\x0f\x00\x2a'

# 0f 00 2e             	verw   (%rsi)
VERW_RSI = b'\x0f\x00\x2e'

# 0f 00 2f             	verw   (%rdi)
VERW_RDI = b'\x0f\x00\x2f'

# 41 0f 00 28          	verw   (%r8)
VERW_R8 = b'\x41\x0f\x00\x28'

# 41 0f 00 29          	verw   (%r9)
VERW_R9 = b'\x41\x0f\x00\x29'

# 41 0f 00 2a          	verw   (%r10)
VERW_R10 = b'\x41\x0f\x00\x2a'

# 41 0f 00 2b          	verw   (%r11)
VERW_R11 = b'\x41\x0f\x00\x2b'

# 41 0f 00 2c 24       	verw   (%r12)
VERW_R12 = b'\x41\x0f\x00\x2c'

# 41 0f 00 6d 00       	verw   0x0(%r13)
VERW_R13 = b'\x41\x0f\x00\x6d\x00'

# 41 0f 00 2e          	verw   (%r14)
VERW_R14 = b'\x41\x0f\x00\x2e'

# 41 0f 00 2f          	verw   (%r15)
VERW_R15 = b'\x41\x0f\x00\x2f'
