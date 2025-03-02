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

rule NodeJsCommandInjection {
    meta:
        description = "Detects Node.js command injection vulnerabilities"
        severity = "critical"
        category = "security"
    strings:
        $child_process = "child_process"
        $exec = /exec\s*\(/
        $spawn = /spawn\s*\(/
        $shell_exec = "execSync"
        $template_literal = /`.*\$\{.*\}.*`/
    condition:
        any of them
}

rule JavaScriptPrototypePollution {
    meta:
        description = "Detects prototype pollution vulnerabilities"
        severity = "high"
        category = "security"
    strings:
        $proto = "__proto__"
        $constructor = "constructor"
        $object_assign = "Object.assign"
        $extend = "$.extend"
        $lodash_merge = "_.merge"
    condition:
        any of them
}

rule JavaScriptXSS {
    meta:
        description = "Detects Cross-Site Scripting vectors"
        severity = "high"
        category = "security"
    strings:
        $dom_xss = /(innerHTML|outerHTML|document\.write|eval)\s*=/
        $dangerous_func = /(setTimeout|setInterval)\s*\(\s*["'].*["']\s*\)/
        $location = "location.href"
        $src_attribute = /src\s*=\s*["'][^"']*\$\{/
        $script_injection = /document\.createElement\s*\(\s*["']script["']\s*\)/
    condition:
        any of them
}

rule JavaScriptUnsafeRegex {
    meta:
        description = "Detects unsafe regular expressions"
        severity = "medium"
        category = "security"
    strings:
        $regex_dos = /RegExp\s*\(\s*["'][^"']*([+*?]|\{,\})\s*["']\)/
        $evil_regex = /\(\.\*\)\+/
        $unbounded = /\{[0-9]+,\}/
    condition:
        any of them
}

rule JavaScriptSecretLeak {
    meta:
        description = "Detects hardcoded secrets and sensitive data"
        severity = "critical"
        category = "security"
    strings:
        $api_key = /(api[_-]?key|apikey)\s*[:=]\s*["'][a-zA-Z0-9_\-]{16,}["']/
        $aws_key = /(aws[_-]?key|aws[_-]?secret)\s*[:=]\s*["'][A-Za-z0-9/+=]{16,}["']/
        $password = /(password|passwd|pwd)\s*[:=]\s*["'][^"']{8,}["']/
        $token = /(token|secret|auth)\s*[:=]\s*["'][a-zA-Z0-9_\-]{16,}["']/
    condition:
        any of them
}

rule NodeJsPathTraversal {
    meta:
        description = "Detects path traversal vulnerabilities"
        severity = "high"
        category = "security"
    strings:
        $read_file = "fs.readFile"
        $write_file = "fs.writeFile"
        $path_join = "path.join"
        $resolve = "path.resolve"
        $normalize = "path.normalize"
        $dots = /\.\.[\\/]/
    condition:
        any of them
}
