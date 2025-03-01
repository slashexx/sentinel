import * as vscode from 'vscode';
import { checkForSecurityIssues, suggestSecurityFix, initializeGemini } from './security';

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
        vscode.window.showInformationMessage('Sentinel initialized successfully with Gemini API');

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
                const startLine = 0;
                const endLine = document.lineCount - 1;
                let context = '';
                for (let i = startLine; i <= endLine; i++) {
                    if (i !== lineNumber - 1) {
                        context += document.lineAt(i).text + '\n';
                    }
                }
                
                // Show progress indicator
                await vscode.window.withProgress(
                    {
                        location: vscode.ProgressLocation.Notification,
                        title: `Generating secure alternative for line ${lineNumber}...`,
                        cancellable: false
                    },
                    async () => {
                        const suggestion = await suggestSecurityFix(issue, code, context);
                        
                        const selection = await vscode.window.showInformationMessage(
                            `Suggestion for line ${lineNumber}:`, 
                            { modal: true, detail: suggestion },
                            'Apply Fix', 'Copy to Clipboard', 'Cancel'
                        );
                        
                        if (selection === 'Apply Fix') {
                            const edit = new vscode.WorkspaceEdit();
                            // Remove any code block markers and language identifiers if present
                            let cleanedSuggestion = suggestion;
                            if (suggestion.startsWith('```')) {
                                // Extract content between code blocks
                                const codeBlockRegex = /```(?:[\w]*\n)?([\s\S]*?)```/;
                                const match = suggestion.match(codeBlockRegex);
                                if (match && match[1]) {
                                    cleanedSuggestion = match[1].trim();
                                }
                            }
                            
                            edit.replace(
                                document.uri, 
                                new vscode.Range(
                                    0, 0, 
                                    document.lineCount - 1, 
                                    document.lineAt(document.lineCount - 1).text.length
                                ),
                                cleanedSuggestion
                            );
                            await vscode.workspace.applyEdit(edit);
                        } else if (selection === 'Copy to Clipboard') {
                            await vscode.env.clipboard.writeText(suggestion);
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
