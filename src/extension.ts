import * as vscode from 'vscode';
import { checkForSecurityIssues, suggestSecurityFix } from './security';

export async function activate(context: vscode.ExtensionContext) {
    console.log('Sentinel is now active!');

    // This securely stores the API key
    try {
        const apiKey = await context.secrets.get('geminiApiKey');
        if (!apiKey) {
            const key = await vscode.window.showInputBox({
                prompt: 'Enter your Google Gemini API key',
                password: true
            });
            if (key) {
                await context.secrets.store('geminiApiKey', key);
                process.env.GEMINI_API_KEY = key;
            } else {
                throw new Error('API key is required for this extension to work');
            }
        } else {
            process.env.GEMINI_API_KEY = apiKey;
        }
    } catch (error) {
        vscode.window.showErrorMessage(`Failed to setup API key: ${error}`);
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
                
                // Show progress indicator
                const fixingMsg = `Generating secure alternative for line ${lineNumber}...`;
                await vscode.window.withProgress(
                    {
                        location: vscode.ProgressLocation.Notification,
                        title: fixingMsg,
                        cancellable: false
                    },
                    async () => {
                        // Get the document to extract some context
                        const document = await vscode.workspace.openTextDocument(vscode.Uri.parse(documentUri));
                        
                        // Get a few lines before and after for context
                        const startLine = Math.max(0, lineNumber - 3);
                        const endLine = Math.min(document.lineCount - 1, lineNumber + 2);
                        let context = '';
                        for (let i = startLine; i <= endLine; i++) {
                            if (i !== lineNumber - 1) { // Skip the problematic line itself
                                context += document.lineAt(i).text + '\n';
                            }
                        }
                        
                        // Get suggestion from Gemini
                        const suggestion = await suggestSecurityFix(issue, code, context);
                        
                        // Show the suggestion to the user
                        const selection = await vscode.window.showInformationMessage(
                            `Suggestion for line ${lineNumber}:`, 
                            { modal: true, detail: suggestion },
                            'Apply Fix', 'Copy to Clipboard', 'Cancel'
                        );
                        
                        if (selection === 'Apply Fix') {
                            const edit = new vscode.WorkspaceEdit();
                            // Find the exact position of the code in the line
                            const line = document.lineAt(lineNumber - 1);
                            const startChar = line.text.indexOf(code);
                            if (startChar !== -1) {
                                const range = new vscode.Range(
                                    lineNumber - 1, startChar,
                                    lineNumber - 1, startChar + code.length
                                );
                                edit.replace(document.uri, range, suggestion);
                                await vscode.workspace.applyEdit(edit);
                            }
                        } else if (selection === 'Copy to Clipboard') {
                            await vscode.env.clipboard.writeText(suggestion);
                            vscode.window.showInformationMessage('Fix copied to clipboard!');
                        }
                    }
                );
            } catch (error) {
                const errorMessage = error instanceof Error ? error.message : 'Unknown error';
                vscode.window.showErrorMessage(`Error generating fix: ${errorMessage}`);
            }
        })
    );

    context.subscriptions.push(disposable);
}

export function deactivate() {}
