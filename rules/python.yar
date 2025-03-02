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

rule PythonDeserializationVulns {
    meta:
        description = "Detects unsafe deserialization"
        severity = "critical"
        category = "security"
    strings:
        $pickle = "pickle.loads"
        $yaml = "yaml.load"
        $marshal = "marshal.loads"
        $jsonpickle = "jsonpickle.decode"
    condition:
        any of them
}

rule PythonCryptoWeakness {
    meta:
        description = "Detects weak cryptographic practices"
        severity = "high"
        category = "security"
    strings:
        $md5 = "hashlib.md5"
        $sha1 = "hashlib.sha1"
        $random = "random.randint"
        $urandom = "os.urandom"
    condition:
        any of them
}

rule PythonInjection {
    meta:
        description = "Detects various injection vulnerabilities"
        severity = "critical"
        category = "security"
    strings:
        $sql = "execute("
        $nosql = "find("
        $template = "Template("
        $subprocess = "subprocess."
        $command = "commands."
    condition:
        any of them
}

rule PythonTemplateInjection {
    meta:
        description = "Detects template injection vulnerabilities"
        severity = "critical"
        category = "security"
    strings:
        $jinja = "render_template_string("
        $mako = "Template("
        $eval_template = "template.render("
        $format_string = ".format("
        $fstring = /f["'].*\{.*\}.*["']/
    condition:
        any of them
}

rule PythonOSCommandInjection {
    meta:
        description = "Detects OS command injection patterns"
        severity = "critical"
        category = "security"
    strings:
        $os_system = "os.system("
        $popen = "os.popen("
        $subprocess_shell = "subprocess.shell = True"
        $spawn = "spawn"
        $command_run = ".run("
        $command_string = /["'].*(\||>|<|;|&).*["']/
    condition:
        any of them
}

rule PythonXXE {
    meta:
        description = "Detects XML External Entity vulnerabilities"
        severity = "high"
        category = "security"
    strings:
        $etree_parse = "etree.parse("
        $xml_load = "xml.load"
        $xmlrpc = "xmlrpclib"
        $dom_parse = "parseString("
        $sax_parse = "sax.parse"
    condition:
        any of them
}

rule PythonUnsafeDeserialization {
    meta:
        description = "Detects unsafe deserialization patterns"
        severity = "critical"
        category = "security"
    strings:
        $pickle_load = /(pickle|cPickle)\.(loads|load)\(/
        $yaml_load = "yaml.load("
        $json_loads = "json.loads("
        $marshal_loads = "marshal.loads("
        $shelve_open = "shelve.open("
        $dill_load = "dill.load"
    condition:
        any of them
}

rule PythonCryptoVulns {
    meta:
        description = "Detects cryptographic vulnerabilities"
        severity = "high"
        category = "security"
    strings:
        $weak_hash = /(md5|sha1)\(/
        $weak_key = /"(SECRET|KEY|SALT)":\s*["'][a-zA-Z0-9]+["']/
        $weak_random = "random.random"
        $des_usage = "Crypto.Cipher.DES"
        $rc4_usage = "Crypto.Cipher.ARC4"
        $blowfish = "Crypto.Cipher.Blowfish"
    condition:
        any of them
}

rule PythonSQLInjection {
    meta:
        description = "Detects SQL injection patterns"
        severity = "critical"
        category = "security"
    strings:
        $raw_sql = /execute\(["'][^"']*\%[^"']*["']/
        $string_concat = /["']SELECT.*\s*\+\s*.*["']/
        $format_string = /["']SELECT.*\{.*\}.*["']/
        $direct_input = /execute\([^"']*request\.(args|form|get|post)/
        $orm_raw = "raw("
    condition:
        any of them
}

rule PythonSecurityMisconfig {
    meta:
        description = "Detects security misconfiguration"
        severity = "high"
        category = "security"
    strings:
        $debug = "DEBUG = True"
        $all_hosts = "host = '0.0.0.0'"
        $disable_csrf = "CSRF_ENABLED = False"
        $disable_security = "SECURITY_ENABLE = False"
        $allow_all = "ALLOWED_HOSTS = ['*']"
        $admin_default = "admin_enabled = True"
    condition:
        any of them
}
