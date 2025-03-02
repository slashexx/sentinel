rule PerlInjection {
    meta:
        description = "Detects command injection in Perl"
        severity = "critical"
        category = "security"
    strings:
        $system = "system "
        $backtick = /`.*`/
        $open = "open("
        $exec = "exec "
        $eval = "eval "
    condition:
        any of them
}

rule PerlTaintMode {
    meta:
        description = "Detects taint mode bypasses"
        severity = "high"
        category = "security"
    strings:
        $untaint = /\$\w+\s*=~\s*\/(.*?)\//
        $no_taint = "-T"
        $user_input = "<STDIN>"
        $param_input = "param("
    condition:
        any of them
}

rule PerlCGIVulns {
    meta:
        description = "Detects CGI.pm vulnerabilities"
        severity = "high"
        category = "security"
    strings:
        $cgi_new = "CGI->new"
        $param = "->param("
        $header = "->header("
        $cookie = "->cookie("
        $unsafe_param = /param\(['"][^'"]+['"]\)/
    condition:
        any of them
}
