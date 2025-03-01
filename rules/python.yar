rule PythonDangerousEval {
    meta:
        description = "Detects usage of eval()"
        severity = "high"
        language = "python"
    strings:
        $eval = "eval("
        $input = "input("
    condition:
        $eval
}

rule PythonDangerousExec {
    meta:
        description = "Detects usage of exec()"
        severity = "high"
        language = "python"
    strings:
        $exec = "exec("
    condition:
        $exec
}

rule PythonHardcodedPassword {
    meta:
        description = "Detects hardcoded passwords"
        severity = "medium"
        language = "python"
    strings:
        $pwd1 = /password\s*=\s*["'][^"']+["']/
        $pwd2 = /passwd\s*=\s*["'][^"']+["']/
    condition:
        any of them
}
