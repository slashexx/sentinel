rule TypeScriptUnsafeAny {
    meta:
        description = "Detects usage of 'any' type"
        severity = "medium"
        language = "typescript"
    strings:
        $any = ": any"
    condition:
        $any
}

rule TypeScriptNoExplicitReturn {
    meta:
        description = "Functions without explicit return types"
        severity = "low"
        language = "typescript"
    strings:
        $func = /function\s+\w+\s*\([^:]+\)\s*{/
    condition:
        $func
}

rule TypeScriptUnsafeAssertion {
    meta:
        description = "Detects unsafe type assertions"
        severity = "medium"
        language = "typescript"
    strings:
        $as = " as any"
        $bang = /!\./
    condition:
        any of them
}
