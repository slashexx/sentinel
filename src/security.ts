import * as vscode from 'vscode';
import { GoogleGenerativeAI } from '@google/generative-ai';

// Initialize Gemini client - you'll need an API key
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY || ''); // Store API key securely
const model = genAI.getGenerativeModel({ model: 'gemini-1.5-pro' });

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

            const diagnostic = new vscode.Diagnostic(
                range,
                pattern.message,
                vscode.DiagnosticSeverity.Warning
            );
            
            // Add data for code fix
            diagnostic.code = {
                value: 'security-issue',
                target: vscode.Uri.parse(`command:sentinel.suggestFix?${encodeURIComponent(JSON.stringify({
                    issue: pattern.message,
                    code: match[0],
                    lineNumber: startPos.line + 1,
                    documentUri: document.uri.toString()
                }))}`)
            };
            
            diagnostics.push(diagnostic);
        }
    });

    // Add diagnostics (warnings) to the editor
    const diagnosticCollection = vscode.languages.createDiagnosticCollection("sentinel");
    diagnosticCollection.set(document.uri, diagnostics);
}

// Function to suggest a fix using Gemini
export async function suggestSecurityFix(issue: string, code: string, context: string = ''): Promise<string> {
    try {
        const prompt = `
I found a security issue in my code: "${issue}"
The problematic code is: \`${code}\`
${context ? `Context: ${context}` : ''}

Please suggest a secure alternative that fixes this issue. 
Provide only the fixed code snippet without explanations.`;

        const result = await model.generateContent(prompt);
        const response = result.response;
        return response.text() || 'No suggestion available.';
    } catch (error) {
        console.error('Error getting suggestion from Gemini:', error);
        return 'Failed to get suggestion. Please check your API key and network connection.';
    }
}
