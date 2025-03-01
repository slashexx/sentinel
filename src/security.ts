import * as vscode from 'vscode';
import * as path from 'path';
import { parseYaraFile } from './parser/yaraParser';
import { YaraRule } from './types/yara';
import { GoogleGenerativeAI } from '@google/generative-ai';

// Initialize Gemini client - you'll need an API key
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY || ''); // Store API key securely
const model = genAI.getGenerativeModel({ model: 'gemini-1.5-pro' });

export function checkForSecurityIssues(document: vscode.TextDocument) {
    const languageId = document.languageId;
    const rulesPath = path.join(__dirname, '..', 'rules', `${languageId}.yar`); // Note: changed extension to .yar
    
    console.log(`Checking document with language: ${languageId}`);
    console.log(`Looking for rules at: ${rulesPath}`);
    
    let rules: YaraRule[] = [];
    try {
        rules = parseYaraFile(rulesPath);
        console.log(`Loaded ${rules.length} rules for ${languageId}`);
    } catch (error) {
        console.error(`Error loading YARA rules:`, error);
        return;
    }

    const text = document.getText();
    const diagnostics: vscode.Diagnostic[] = [];

    rules.forEach((rule) => {
        console.log(`Applying rule: ${rule.name}`);
        rule.strings.forEach((str) => {
            const regex = str.isRegex ? new RegExp(str.value, 'g') : new RegExp(escapeRegExp(str.value), 'g');
            console.log(`Checking pattern: ${regex}`);
            let match;
            
            while ((match = regex.exec(text)) !== null) {
                console.log(`Found match at index ${match.index}:`, match[0]);
                const pos = document.positionAt(match.index);
                const endPos = document.positionAt(match.index + match[0].length);
                
                const diagnostic = new vscode.Diagnostic(
                    new vscode.Range(pos, endPos),
                    `⚠️ ${rule.name}: ${rule.metadata?.description || 'Security issue detected'}`,
                    rule.metadata?.severity === 'high' 
                        ? vscode.DiagnosticSeverity.Error 
                        : vscode.DiagnosticSeverity.Warning
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
    });

    console.log(`Found ${diagnostics.length} issues`);
    const diagnosticCollection = vscode.languages.createDiagnosticCollection("sentinel");
    diagnosticCollection.set(document.uri, diagnostics);
}

function escapeRegExp(string: string): string {
    return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
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
