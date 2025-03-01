rule javascript_eval {
    metadata:
        description = "Detects use of eval()"
        severity = "high"
        category = "code-quality"
    
    strings:
        $eval = "eval("
    
    condition:
        any of them
}

rule javascript_innerHTML {
    metadata:
        description = "Detects unsafe innerHTML usage"
        severity = "high"
        category = "security"
    
    strings:
        $innerHTML = ".innerHTML ="
    
    condition:
        any of them
}
