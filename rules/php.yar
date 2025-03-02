rule PHPCommandInjection {
    meta:
        description = "Detects command injection vectors"
        severity = "critical"
        category = "security"
    strings:
        $exec = "exec("
        $shell = "shell_exec("
        $system = "system("
        $passthru = "passthru("
        $backtick = /`.*`/
    condition:
        any of them
}

rule PHPFileInclusion {
    meta:
        description = "Detects dangerous file inclusion"
        severity = "high"
        category = "security"
    strings:
        $include = "include($_"
        $require = "require($_"
        $include_once = "include_once($_"
        $require_once = "require_once($_"
    condition:
        any of them
}

rule PHPSerialize {
    meta:
        description = "Detects unsafe serialization"
        severity = "high"
        category = "security"
    strings:
        $unserialize = "unserialize("
        $objectlike = "O:" // PHP serialized object pattern
    condition:
        any of them
}
