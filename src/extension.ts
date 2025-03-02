import * as vscode from 'vscode';
import { checkForSecurityIssues, suggestSecurityFix, initializeGemini } from './security';
import { GeminiResponse, CodeFix } from './types/fixes';

interface IndentationInfo {
    indent: string;
    level: number;
}

function getIndentation(line: string): IndentationInfo {
    const match = line.match(/^(\s+)/);
    const indent = match ? match[1] : '';
    // Calculate indentation level (assuming 4 spaces or 1 tab per level)
    const level = indent.replace(/\t/g, '    ').length / 4;
    return { indent, level };
}

function preserveIndentation(originalLine: string, newCode: string): string {
    const { indent } = getIndentation(originalLine);
    // Split multiline code and preserve indentation for each line
    return newCode.split('\n').map((line, i) => {
        // First line uses original indentation
        if (i === 0) {
            return indent + line.trimStart();
        }
        // Subsequent lines adjust indentation relative to the first line
        const additionalIndent = getIndentation(line).level;
        return indent + '    '.repeat(additionalIndent) + line.trimStart();
    }).join('\n');
}

async function showDiffPreview(
    document: vscode.TextDocument,
    fixes: CodeFix[]
): Promise<boolean> {
    // Get the active text editor
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        throw new Error('No active editor found');
    }

    // Create decorations for the changes
    const deleteDecoration = vscode.window.createTextEditorDecorationType({
        backgroundColor: new vscode.ThemeColor('diffEditor.removedTextBackground'),
        isWholeLine: true,
    });
    
    const addDecoration = vscode.window.createTextEditorDecorationType({
        backgroundColor: new vscode.ThemeColor('diffEditor.insertedTextBackground'),
        isWholeLine: true,
    });

    try {
        // Apply decorations to show the diff
        const deletedRanges: vscode.Range[] = [];
        const addedRanges: vscode.Range[] = [];

        fixes.forEach(fix => {
            const line = fix.lineNumber - 1;
            const originalLine = document.lineAt(line).text;
            const suggestedCode = preserveIndentation(originalLine, fix.suggestedCode);
            fix.suggestedCode = suggestedCode; // Update the fix with proper indentation
            
            const range = new vscode.Range(
                new vscode.Position(line, 0),
                new vscode.Position(line, originalLine.length)
            );
            deletedRanges.push(range);
            addedRanges.push(range);
        });

        editor.setDecorations(deleteDecoration, deletedRanges);
        editor.setDecorations(addDecoration, addedRanges);

        // Show the changes in a preview panel
        const changesDetail = fixes.map(fix => 
            `Line ${fix.lineNumber}:\n` +
            `Current:  ${fix.originalCode}\n` +
            `Proposed: ${fix.suggestedCode}\n` +
            `Reason: ${fix.explanation}`
        ).join('\n\n');

        const choice = await vscode.window.showInformationMessage(
            'Review the highlighted changes. Would you like to apply these security fixes?',
            { modal: true, detail: changesDetail },
            'Apply Fixes', 'Cancel'
        );

        return choice === 'Apply Fixes';
    } finally {
        // Clean up decorations
        deleteDecoration.dispose();
        addDecoration.dispose();
    }
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
                        title: "Analyzing security issue...",
                        cancellable: false
                    },
                    async () => {
                        const suggestion = await suggestSecurityFix(issue, code, context);
                        
                        // Update the fixes with the correct line number
                        suggestion.fixes = suggestion.fixes.map(fix => ({
                            ...fix,
                            lineNumber: lineNumber,
                            originalCode: code
                        }));
                        
                        // Show preview and get approval
                        const approved = await showDiffPreview(document, suggestion.fixes);
                        
                        if (approved) {
                            const edit = new vscode.WorkspaceEdit();
                            for (const fix of suggestion.fixes) {
                                const line = fix.lineNumber - 1;
                                const originalLine = document.lineAt(line).text;
                                const lineText = document.lineAt(line).text;
                                const range = new vscode.Range(
                                    new vscode.Position(line, 0),
                                    new vscode.Position(line, lineText.length)
                                );
                                
                                // Preserve indentation when applying the fix
                                const suggestedCode = preserveIndentation(originalLine, fix.suggestedCode);
                                edit.replace(document.uri, range, suggestedCode);
                            }
                            await vscode.workspace.applyEdit(edit);
                            vscode.window.showInformationMessage('Security fixes applied successfully!');
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

function createDiffView(fixes: CodeFix[]): string {
    return fixes.map(fix => `Line ${fix.lineNumber}:
\`\`\`diff
- ${fix.originalCode}
+ ${fix.suggestedCode}
\`\`\`
Explanation: ${fix.explanation || ''}`).join('\n\n');
}

export function deactivate() {}
