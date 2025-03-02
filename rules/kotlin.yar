rule KotlinReflection {
    meta:
        description = "Detects unsafe reflection usage"
        severity = "high"
        category = "security"
    strings:
        $class_loader = "ClassLoader"
        $reflection = "::class.java"
        $get_declared = "getDeclaredMethod"
        $kotlin_reflect = "kotlin.reflect"
    condition:
        any of them
}

rule KotlinCoroutineLeaks {
    meta:
        description = "Detects potential coroutine leaks"
        severity = "medium"
        category = "resource_management"
    strings:
        $global_scope = "GlobalScope"
        $launch = "launch"
        $async = "async"
        $no_context = "withContext"
        $supervisor = "SupervisorJob"
    condition:
        any of them
}

rule KotlinSerialization {
    meta:
        description = "Detects unsafe serialization"
        severity = "high"
        category = "security"
    strings:
        $serializable = "@Serializable"
        $json_default = "Json.Default"
        $transient = "@Transient"
        $custom_serial = "KSerializer"
    condition:
        any of them
}
