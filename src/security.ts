import * as vscode from 'vscode';
import * as path from 'path';
import { parseYaraFile } from './parser/yaraParser';
import { YaraRule } from './types/yara';

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
                
                diagnostics.push(new vscode.Diagnostic(
                    new vscode.Range(pos, endPos),
                    `⚠️ ${rule.name}: ${rule.metadata?.description || 'Security issue detected'}`,
                    rule.metadata?.severity === 'high' 
                        ? vscode.DiagnosticSeverity.Error 
                        : vscode.DiagnosticSeverity.Warning
                ));
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
