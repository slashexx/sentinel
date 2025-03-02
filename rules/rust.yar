rule RustUnsafeBlocks {
    meta:
        description = "Detects unsafe blocks and functions"
        severity = "high"
        category = "memory_safety"
    strings:
        $unsafe_block = "unsafe {"
        $unsafe_fn = "unsafe fn"
        $unsafe_trait = "unsafe trait"
        $raw_pointer = "*mut "
        $raw_const_pointer = "*const "
    condition:
        any of them
}

rule RustMemoryErrors {
    meta:
        description = "Detects potential memory safety issues"
        severity = "high"
        category = "memory_safety"
    strings:
        $mem_forget = "mem::forget"
        $box_leak = "Box::leak"
        $transmute = "mem::transmute"
        $from_raw = "from_raw"
        $as_ptr = "as_ptr"
    condition:
        any of them
}

rule RustThreading {
    meta:
        description = "Detects unsafe threading patterns"
        severity = "medium"
        category = "concurrency"
    strings:
        $send_sync = "!Send"
        $mutex_poison = "MutexGuard"
        $atomic = "AtomicUsize"
        $thread_spawn = "thread::spawn"
    condition:
        any of them
}

rule RustFFI {
    meta:
        description = "Detects unsafe FFI usage"
        severity = "critical"
        category = "security"
    strings:
        $extern_c = "extern \"C\""
        $link_name = "#[link_name"
        $repr_c = "#[repr(C)]"
        $c_void = "c_void"
    condition:
        any of them
}

rule RustCryptoMisuse {
    meta:
        description = "Detects cryptographic implementation issues"
        severity = "critical"
        category = "security"
    strings:
        $rand = "rand::thread_rng()"
        $weak_rng = "rand::Rng"
        $custom_crypto = "impl Cipher"
        $block_modes = /(ECB|CBC|CTR)Mode/
    condition:
        any of them
}

rule RustNetworkVulns {
    meta:
        description = "Detects network-related vulnerabilities"
        severity = "high"
        category = "security"
    strings:
        $tls_verify = "danger_accept_invalid_certs"
        $bind_all = "0.0.0.0"
        $raw_sock = "raw_socket"
        $no_timeout = "set_read_timeout(None)"
    condition:
        any of them
}

rule RustDeserializationUnsafe {
    meta:
        description = "Detects unsafe deserialization patterns"
        severity = "high"
        category = "security"
    strings:
        $serde_untrusted = "serde_json::from_str"
        $bincode = "bincode::deserialize"
        $custom_deserialize = "#[derive(Deserialize)]"
        $yaml_load = "serde_yaml::from_str"
    condition:
        any of them
}
