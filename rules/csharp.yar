rule CSharpUnsafeCode {
    meta:
        description = "Detects unsafe code blocks"
        severity = "medium"
        category = "security"
    strings:
        $unsafe = "unsafe "
        $fixed = "fixed ("
        $stackalloc = "stackalloc"
    condition:
        any of them
}

rule CSharpDangerousMethods {
    meta:
        description = "Detects potentially dangerous method calls"
        severity = "high"
        category = "security"
    strings:
        $process = "Process.Start("
        $shell = "Shell.Execute"
        $reflection = "Assembly.Load("
        $serialize = "BinaryFormatter"
    condition:
        any of them
}

rule CSharpXMLInjection {
    meta:
        description = "Detects XML injection vulnerabilities"
        severity = "high"
        category = "security"
    strings:
        $xpath = "XPath.Evaluate"
        $xslt = "XslTransform"
        $xmldoc = "XmlDocument.Load("
    condition:
        any of them
}
