rule GenericSQLInjection {
    meta:
        description = "Detects generic SQL injection patterns"
        severity = "critical"
        category = "security"
    strings:
        // Common SQL injection patterns
        $union = /.*(\s|%20|%09)+UNION(\s|%20|%09)+SELECT.*/i
        $comment = /.*(-|--)(\s|%20|%09)*$.*/
        $or_condition = /.*([\s)]|%20|%09)+OR(\s|%20|%09)+[\'\"]*\d+[\'\"]*.*/i
        $batch = /.*(;)(\s|%20|%09)*(SELECT|INSERT|UPDATE|DELETE|DROP).*/i
        $sleep = /(WAITFOR(\s|%20|%09)+DELAY|SLEEP\(|pg_sleep).*/i
        $hex_encode = /0x[0-9a-fA-F]+/
    condition:
        any of them
}

rule ParameterizedQueryBypass {
    meta:
        description = "Detects attempts to bypass parameterized queries"
        severity = "critical"
        category = "security"
    strings:
        $concat_param = /\+(\s|%20|%09)*(request|param|args|post|get|input)/i
        $string_format = /(format|sprintf|concat)\s*\(/
        $template_string = /`.*\$\{.*\}.*`/
        $string_builder = /(StringBuilder|StringBuffer|append)/
    condition:
        any of them
}

rule SQLErrorLeakage {
    meta:
        description = "Detects potential SQL error leakage"
        severity = "medium"
        category = "security"
    strings:
        $error_display = /(SQLException|MySQLError|OracleError|SQLiteError)/
        $stack_trace = /(stacktrace|error_reporting|display_errors)/
        $debug_mode = /(debug|development)(\s|%20|%09)*=(\s|%20|%09)*true/i
    condition:
        any of them
}

rule DatabaseConnectionMisconfig {
    meta:
        description = "Detects database connection misconfigurations"
        severity = "high"
        category = "security"
    strings:
        $root_user = /(root|admin|sa)[@:]/i
        $weak_password = /password(\s|%20|%09)*=(\s|%20|%09)*[\'\"](123|admin|password|root)/i
        $connection_string = /(jdbc|mongodb|mysql|postgresql):\/\//i
        $connection_config = /(connection_string|database_url)(\s|%20|%09)*=/i
    condition:
        any of them
}
