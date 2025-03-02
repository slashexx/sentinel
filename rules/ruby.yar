rule RubyCommandExecution {
    meta:
        description = "Detects dangerous command execution"
        severity = "critical"
        category = "security"
    strings:
        $system = "system("
        $exec = "exec("
        $backtick = /`.*`/
        $eval = "eval("
    condition:
        any of them
}

rule RubyDeserialization {
    meta:
        description = "Detects unsafe deserialization"
        severity = "high"
        category = "security"
    strings:
        $yaml = "YAML.load"
        $marshal = "Marshal.load"
        $json = "JSON.load"
    condition:
        any of them
}

rule RubyFileAccess {
    meta:
        description = "Detects unsafe file operations"
        severity = "medium"
        category = "security"
    strings:
        $open = "File.open"
        $read = "File.read"
        $write = "File.write"
        $send_file = "send_file"
    condition:
        any of them
}

rule RubyRailsVulns {
    meta:
        description = "Detects Rails-specific vulnerabilities"
        severity = "high"
        category = "security"
    strings:
        $mass_assign = "params.permit!"
        $sql_injection = ".where(params["
        $render_inline = "render inline:"
        $auth_skip = "skip_before_action :authenticate"
        $csrf_disable = "protect_from_forgery except:"
    condition:
        any of them
}

rule RubySSRF {
    meta:
        description = "Detects Server-Side Request Forgery vectors"
        severity = "critical"
        category = "security"
    strings:
        $http_get = "Net::HTTP.get"
        $open_uri = "open-uri"
        $curl = "Curl::Easy"
        $faraday = "Faraday.new"
        $http_client = "HTTPClient.new"
    condition:
        any of them
}

rule RubyEncryptionWeak {
    meta:
        description = "Detects weak encryption practices"
        severity = "high"
        category = "security"
    strings:
        $md5 = "Digest::MD5"
        $sha1 = "Digest::SHA1"
        $base64 = "Base64.encode64"
        $aes_ecb = "cipher.encrypt_mode = :ECB"
        $weak_key = /(key|iv)\s*=\s*["'][a-zA-Z0-9]+["']/
    condition:
        any of them
}
