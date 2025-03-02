rule PythonSQLInjection {
    meta:
        description = "Detects Python-specific SQL injection"
        severity = "critical"
        category = "security"
    strings:
        $django_raw = "raw("
        $cursor_execute = "cursor.execute("
        $format_string = "%(.*?)s"
        $string_concat = "\" + "
        $f_string = /f["']SELECT.*\{.*\}.*["']/i
        $orm_extra = ".extra(where="
        $filter_raw = ".filter(raw="
    condition:
        any of them
}

rule JavaSQLInjection {
    meta:
        description = "Detects Java-specific SQL injection"
        severity = "critical"
        category = "security"
    strings:
        $statement = "createStatement("
        $prepared = "prepareStatement("
        $hibernate_query = "createQuery("
        $jpa_query = "createNativeQuery("
        $mybatis = "${" 
        $string_format = "String.format("
        $builder_append = ".append(\"SELECT"
    condition:
        any of them
}

rule PHPSQLInjection {
    meta:
        description = "Detects PHP-specific SQL injection"
        severity = "critical"
        category = "security"
    strings:
        $mysql_query = "mysql_query("
        $mysqli_query = "mysqli_query("
        $pdo_query = "->query("
        $raw_input = "$_GET["
        $post_input = "$_POST["
        $request = "$_REQUEST["
        $variable_interpolation = /["'].*\$.*["']/
    condition:
        any of them
}

rule NodeSQLInjection {
    meta:
        description = "Detects Node.js-specific SQL injection"
        severity = "critical"
        category = "security"
    strings:
        $sequelize_raw = "sequelize.query("
        $mongoose_find = "$where:"
        $template_literal = /`SELECT.*\${.*}`/i
        $knex_raw = "knex.raw("
        $prisma_raw = "prisma.$executeRaw"
        $query_concat = ".query(\"SELECT" 
    condition:
        any of them
}

rule RubySQLInjection {
    meta:
        description = "Detects Ruby-specific SQL injection"
        severity = "critical"
        category = "security"
    strings:
        $active_record = "find_by_sql"
        $execute = "execute("
        $string_interpolation = /#\{.*\}/
        $raw_condition = ".where(\"" 
        $connection_execute = "connection.execute"
        $sanitize_bypass = "sanitize_sql"
    condition:
        any of them
}
