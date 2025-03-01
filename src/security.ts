import * as vscode from 'vscode';

export function checkForSecurityIssues(document: vscode.TextDocument) {
    const text = document.getText();
    const diagnostics: vscode.Diagnostic[] = [];

    // Define some simple security patterns (you can replace this with YARA later)
    const patterns = [
        { regex: /eval\(/g, message: "⚠️ Avoid using 'eval()', it's a security risk!" },
        { regex: /exec\(/g, message: "⚠️ Using 'exec()' can lead to command injection!" },
        { regex: /password\s*=\s*['"].+['"]/g, message: "⚠️ Hardcoded passwords detected!" }
    ];

    patterns.forEach(pattern => {
        let match;
        while ((match = pattern.regex.exec(text)) !== null) {
            const startPos = document.positionAt(match.index);
            const endPos = document.positionAt(match.index + match[0].length);
            const range = new vscode.Range(startPos, endPos);

            diagnostics.push(new vscode.Diagnostic(
                range,
                pattern.message,
                vscode.DiagnosticSeverity.Warning
            ));
        }
    });

    // Add diagnostics (warnings) to the editor
    const diagnosticCollection = vscode.languages.createDiagnosticCollection("sentinel");
    diagnosticCollection.set(document.uri, diagnostics);
}
