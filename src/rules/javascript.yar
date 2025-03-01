rule JavaScriptDangerousEval {
    meta:
        description = "Detects usage of eval()"
        severity = "high"
        language = "javascript"
    strings:
        $eval = "eval("
    condition:
        $eval
}

rule JavaScriptXSS {
    meta:
        description = "Detects potential XSS vulnerabilities"
        severity = "high"
        language = "javascript"
    strings:
        $innerHTML = "innerHTML"
        $docWrite = "document.write("
        $innerHtmlReact = "dangerouslySetInnerHTML"
    condition:
        any of them
}

rule JavaScriptUnsafeJQuery {
    meta:
        description = "Detects unsafe jQuery usage"
        severity = "medium"
        language = "javascript"
    strings:
        $html = "$('").append("
        $rawHtml = "html("
    condition:
        any of them
}
