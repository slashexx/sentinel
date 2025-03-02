rule GoUnsafeUsage {
    meta:
        description = "Detects usage of unsafe package"
        severity = "medium"
        category = "security"
    strings:
        $unsafe = "unsafe."
        $pointer = "Pointer"
        $sizeof = "Sizeof"
    condition:
        any of them
}

rule GoWeakCrypto {
    meta:
        description = "Detects weak cryptographic implementations"
        severity = "high"
        category = "security"
    strings:
        $md5 = "md5."
        $sha1 = "sha1."
        $rc4 = "rc4."
        $des = "des."
    condition:
        any of them
}

rule GoSQLInjection {
    meta:
        description = "Detects potential SQL injection points"
        severity = "high"
        category = "security"
    strings:
        $rawQuery = "db.Query("
        $exec = "db.Exec("
        $sprintf = "fmt.Sprintf(\"SELECT"
    condition:
        any of them
}
