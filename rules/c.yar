rule CBufferOverflow {
    meta:
        description = "Detects potential buffer overflow vectors"
        severity = "critical"
        category = "memory_safety"
    strings:
        $gets = "gets("
        $strcpy = "strcpy("
        $strcat = "strcat("
        $sprintf = "sprintf("
        $scanf = "scanf("
        $unsafe_array = /char\s+[a-zA-Z_][a-zA-Z0-9_]*\[[0-9]+\]/
    condition:
        any of them
}

rule CDangerousMemory {
    meta:
        description = "Detects dangerous memory operations"
        severity = "high"
        category = "memory_safety"
    strings:
        $malloc = "malloc("
        $free = "free("
        $realloc = "realloc("
        $memcpy = "memcpy("
        $memmove = "memmove("
        $double_free = /free\s*\([^)]+\).*free\s*\([^)]+\)/
    condition:
        any of them
}

rule CFormatString {
    meta:
        description = "Detects format string vulnerabilities"
        severity = "critical"
        category = "security"
    strings:
        $printf = "printf("
        $fprintf = "fprintf("
        $snprintf = "snprintf("
        $format_direct = /(f|s|v|)[n]?printf\s*\([^,]+\)/
    condition:
        any of them
}

rule CSystemCalls {
    meta:
        description = "Detects dangerous system calls"
        severity = "high"
        category = "security"
    strings:
        $system = "system("
        $popen = "popen("
        $exec = "exec"
        $fork = "fork("
        $shellcode = /\{\s*(?:0x[0-9a-fA-F]{2}\s*,\s*){8,}\s*}/
    condition:
        any of them
}
