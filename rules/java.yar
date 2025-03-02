rule JavaDeserialization {
    meta:
        description = "Detects unsafe Java deserialization"
        severity = "high"
        category = "security"
    strings:
        $readObject = "readObject("
        $readObjectNoData = "readObjectNoData("
        $readExternal = "readExternal("
    condition:
        any of them
}

rule JavaSQLInjection {
    meta:
        description = "Detects potential SQL injection vectors"
        severity = "critical"
        category = "security"
    strings:
        $stmt1 = "Statement.execute"
        $stmt2 = "createStatement("
        $concat = ".append(\"SELECT"
        $format = "String.format(\"SELECT"
    condition:
        any of them
}

rule JavaHardcodedSecrets {
    meta:
        description = "Detects hardcoded credentials"
        severity = "high"
        category = "security"
    strings:
        $pwd = /password\s*=\s*["'][^"']+["']/
        $key = /key\s*=\s*["'][^"']+["']/
        $token = /token\s*=\s*["'][^"']+["']/
        $secret = /secret\s*=\s*["'][^"']+["']/
    condition:
        any of them
}

rule JavaSpringVulns {
    meta:
        description = "Detects Spring Framework vulnerabilities"
        severity = "high"
        category = "security"
    strings:
        $rce = "@RequestMapping(value = \"*\")"
        $ssrf = "RestTemplate"
        $el_injection = "#{expression}"
        $path_traversal = "file.getCanonicalPath()"
        $actuator = "management.endpoints.web.exposure.include=*"
    condition:
        any of them
}

rule JavaSecurityConfig {
    meta:
        description = "Detects security misconfiguration"
        severity = "high"
        category = "security"
    strings:
        $csrf_disable = ".csrf().disable()"
        $cors_all = "addAllowedOrigin(\"*\")"
        $auth_all = "permitAll()"
        $debug_mode = "application.properties"
    condition:
        any of them
}

rule JavaLogInjection {
    meta:
        description = "Detects log injection vulnerabilities"
        severity = "medium"
        category = "security"
    strings:
        $log4j = "${jndi:"
        $logger_format = "logger.info("
        $println = "System.out.println("
        $stack_trace = "printStackTrace()"
    condition:
        any of them
}
