import * as vscode from 'vscode';
import * as path from 'path';
import { parseYaraFile } from './parser/yaraParser';
import { YaraRule } from './types/yara';
import { GoogleGenerativeAI } from '@google/generative-ai';
import { GeminiResponse, CodeFix } from './types/fixes';

let genAI: GoogleGenerativeAI | null = null;
let model: any = null;

export function initializeGemini(apiKey: string) {
    if (!apiKey) {
        throw new Error('API key is required');
    }
    genAI = new GoogleGenerativeAI(apiKey);
    model = genAI.getGenerativeModel({ model: 'gemini-1.5-pro' });
}

export function checkForSecurityIssues(document: vscode.TextDocument) {
    const languageId = document.languageId;
    const config = vscode.workspace.getConfiguration('sentinel');
    const customRulesPath = config.get<string>('customRulesPath');
    const defaultRulesPath = path.join(__dirname, '..', 'rules', `${languageId}.yar`);
    const rulesPath = customRulesPath || defaultRulesPath;

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
                        issue: rule.metadata?.description || 'Security issue detected',
                        code: match[0],
                        lineNumber: pos.line + 1,
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

function cleanGeminiResponse(text: string): string {
    // Remove code block markers and language identifiers
    const codeBlockRegex = /```(?:json\n)?([\s\S]*?)```/;
    const match = text.match(codeBlockRegex);
    if (match && match[1]) {
        return match[1].trim();
    }
    return text.trim();
}

// Function to suggest a fix using Gemini
export async function suggestSecurityFix(issue: string, code: string, context: string = ''): Promise<GeminiResponse> {
    if (!model) {
        throw new Error('Gemini API not initialized');
    }

    // Get the matching YARA rule based on the issue
    const languageId = vscode.window.activeTextEditor?.document.languageId || '';
    const rulesPath = path.join(__dirname, '..', 'rules', `${languageId}.yar`);
    const rules = parseYaraFile(rulesPath);
    const matchingRule = rules.find(r => r.metadata?.description === issue);

    const prompt = `
As a security expert, analyze this code issue and provide a secure fix. 
Consider this security context:
Rule: ${matchingRule?.name || 'Unknown'}
Severity: ${matchingRule?.metadata?.severity || 'Unknown'}
Description: ${issue}

Provide a fix in the following JSON format (without any markdown or code blocks):

{
    "fixes": [
        {
            "lineNumber": <line number to change>,
            "originalCode": "<problematic code>",
            "suggestedCode": "<secure alternative with proper relative indentation>",
            "explanation": "<brief explanation>"
        }
    ],
    "overallExplanation": "<general explanation of the fix>"
}

Problematic Code: \`${code}\`
${context ? `Context: ${context}` : ''}`;

    try {
        const result = await model.generateContent(prompt);
        const response = result.response;
        const cleanedResponse = cleanGeminiResponse(response.text());
        const jsonResponse = JSON.parse(cleanedResponse);
        return jsonResponse as GeminiResponse;
    } catch (error) {
        console.error('Error parsing Gemini response:', error);
        throw new Error('Failed to parse Gemini response. Please try again.');
    }
}

function createDiffView(fixes: CodeFix[]): string {
    return fixes.map(fix => `Line ${fix.lineNumber}:
\`\`\`diff
- ${fix.originalCode}
+ ${fix.suggestedCode}
\`\`\`
Explanation: ${fix.explanation || ''}`).join('\n\n');
}

export async function activate(context: vscode.ExtensionContext) {
    console.log('Sentinel extension is now active!');

    // Initialize API key
    try {
        let apiKey = await context.secrets.get('geminiApiKey');
        console.log('Checking for existing API key:', apiKey ? 'Found' : 'Not found');

        if (!apiKey) {
            console.log('Prompting user for API key...');
            const key = await vscode.window.showInputBox({
                title: 'Gemini API Key Required',
                prompt: 'Please enter your Google Gemini API key to enable security suggestions',
                password: true,
                ignoreFocusOut: true, // Prevents the input box from closing when focus is lost
                placeHolder: 'Enter your Gemini API key here',
                validateInput: text => {
                    return text && text.length > 10 ? null : 'Please enter a valid API key (longer than 10 characters)';
                }
            });

            if (!key) {
                throw new Error('No API key provided');
            }

            console.log('New API key received, storing...');
            await context.secrets.store('geminiApiKey', key);
            apiKey = key;
        }

        // Initialize Gemini with the API key
        console.log('Initializing Gemini...');
        initializeGemini(apiKey);
        vscode.window.showInformationMessage('Sentinel initialized successfully.');

    } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error';
        console.error('Failed to initialize Gemini:', errorMessage);
        vscode.window.showErrorMessage(`Failed to initialize Sentinel: ${errorMessage}`);
        return;
    }

    let disposable = vscode.workspace.onDidChangeTextDocument(event => {
        checkForSecurityIssues(event.document);
    });

    // Also check when a document is opened
    vscode.workspace.onDidOpenTextDocument(document => {
        checkForSecurityIssues(document);
    });

    const diagnosticCollection = vscode.languages.createDiagnosticCollection("sentinel");
    context.subscriptions.push(diagnosticCollection);

    // Register command to suggest fixes
    context.subscriptions.push(
        vscode.commands.registerCommand('sentinel.suggestFix', async (args: {
            issue: string;
            code: string;
            lineNumber: number;
            documentUri: string;
        }) => {
            try {
                const { issue, code, lineNumber, documentUri } = args;
                
                const document = await vscode.workspace.openTextDocument(vscode.Uri.parse(documentUri));
                
                // Get context from surrounding lines
                const startLine = Math.max(0, lineNumber - 3);
                const endLine = Math.min(document.lineCount - 1, lineNumber + 3);
                const context = Array.from(
                    { length: endLine - startLine + 1 },
                    (_, i) => document.lineAt(startLine + i).text
                ).join('\n');
                
                await vscode.window.withProgress(
                    {
                        location: vscode.ProgressLocation.Notification,
                        title: `Generating secure alternative for line ${lineNumber}...`,
                        cancellable: false
                    },
                    async () => {
                        const suggestion = await suggestSecurityFix(issue, code, context);
                        const diffView = createDiffView(suggestion.fixes);
                        
                        const selection = await vscode.window.showInformationMessage(
                            `Suggestion for line ${lineNumber}:`, 
                            { modal: true, detail: diffView },
                            'Apply Fix', 'Copy to Clipboard', 'Cancel'
                        );
                        
                        if (selection === 'Apply Fix') {
                            const edit = new vscode.WorkspaceEdit();
                            const line = lineNumber - 1;
                            const range = new vscode.Range(line, 0, line, document.lineAt(line).text.length);
                            
                            // Use the first fix's suggested code
                            if (suggestion.fixes.length > 0) {
                                edit.replace(document.uri, range, suggestion.fixes[0].suggestedCode);
                                await vscode.workspace.applyEdit(edit);
                            }
                        } else if (selection === 'Copy to Clipboard') {
                            await vscode.env.clipboard.writeText(suggestion.fixes.map(f => f.suggestedCode).join('\n'));
                            vscode.window.showInformationMessage('Fix copied to clipboard!');
                        }
                    }
                );
            } catch (error) {
                vscode.window.showErrorMessage(`Error generating fix: ${error instanceof Error ? error.message : 'Unknown error'}`);
            }
        })
    );

    context.subscriptions.push(disposable);

    let analyzeDisposable = vscode.commands.registerCommand('sentinel.analyze', () => {
        vscode.window.showInformationMessage('Running Sentinel security analysis...');
    });

    context.subscriptions.push(analyzeDisposable);
}

export function deactivate() {}
