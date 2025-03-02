rule CppUnsafeSTL {
    meta:
        description = "Detects unsafe STL usage"
        severity = "medium"
        category = "security"
    strings:
        $vector_access = ".at("
        $iterator_invalidation = /iterator\s+[a-zA-Z_][a-zA-Z0-9_]*\s*=/
        $unsafe_cast = "reinterpret_cast"
        $c_style_cast = /\([a-zA-Z_][a-zA-Z0-9_]*\s*\*\)/
    condition:
        any of them
}

rule CppMemoryLeaks {
    meta:
        description = "Detects potential memory leaks"
        severity = "high"
        category = "memory_safety"
    strings:
        $new_op = "new "
        $delete_op = "delete "
        $new_array = "new[]"
        $delete_array = "delete[]"
        $shared_ptr = "shared_ptr"
        $unique_ptr = "unique_ptr"
        $raw_ptr = /[a-zA-Z_][a-zA-Z0-9_]*\s*\*\s*[a-zA-Z_][a-zA-Z0-9_]*\s*=/
    condition:
        any of them
}

rule CppExceptionUnsafe {
    meta:
        description = "Detects exception-unsafe code"
        severity = "medium"
        category = "error_handling"
    strings:
        $catch_all = "catch(...)"
        $noexcept = "noexcept"
        $throw_in_destructor = /~[a-zA-Z_][a-zA-Z0-9_]*\s*\([^)]*\)\s*\{[^}]*throw/
    condition:
        any of them
}

rule CppThreadUnsafe {
    meta:
        description = "Detects thread-unsafe patterns"
        severity = "high"
        category = "concurrency"
    strings:
        $singleton = /static\s+[a-zA-Z_][a-zA-Z0-9_]*\s*\*\s*instance/
        $global_var = /static\s+[a-zA-Z_][a-zA-Z0-9_]*\s+[a-zA-Z_][a-zA-Z0-9_]*\s*=/
        $mutex = "mutex"
        $lock_guard = "lock_guard"
        $atomic = "atomic"
    condition:
        any of them
}

rule CppModernVulns {
    meta:
        description = "Detects modern C++ vulnerabilities"
        severity = "high"
        category = "security"
    strings:
        $move_semantics = /std::move\s*\([^)]+\)/
        $lambda_capture = /\[\s*&\s*\]/
        $template_injection = /template\s*<\s*typename\s*.*\s*>/
        $constexpr_abuse = /constexpr\s+.*\s+operator\s*\(/
    condition:
        any of them
}

rule CppNetworkVulns {
    meta:
        description = "Detects networking vulnerabilities"
        severity = "critical"
        category = "security"
    strings:
        $socket = "socket("
        $bind = "bind("
        $connect = "connect("
        $ssl_verify = "SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE"
        $raw_packet = "raw_socket"
    condition:
        any of them
}

rule CppContainerMisuse {
    meta:
        description = "Detects container misuse"
        severity = "medium"
        category = "security"
    strings:
        $vector_resize = ".resize("
        $iterator_invalid = "erase("
        $emplace_back = "emplace_back"
        $reserve = ".reserve("
    condition:
        any of them
}
