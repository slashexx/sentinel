"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.activate = activate;
exports.deactivate = deactivate;
const vscode = __importStar(require("vscode"));
const security_1 = require("./security");
function getIndentation(line) {
    const match = line.match(/^(\s+)/);
    const indent = match ? match[1] : '';
    // Calculate indentation level (assuming 4 spaces or 1 tab per level)
    const level = indent.replace(/\t/g, '    ').length / 4;
    return { indent, level };
}
function preserveIndentation(originalLine, newCode) {
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
async function showDiffPreview(document, fixes) {
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
        const deletedRanges = [];
        const addedRanges = [];
        fixes.forEach(fix => {
            const line = fix.lineNumber - 1;
            const originalLine = document.lineAt(line).text;
            const suggestedCode = preserveIndentation(originalLine, fix.suggestedCode);
            fix.suggestedCode = suggestedCode; // Update the fix with proper indentation
            const range = new vscode.Range(new vscode.Position(line, 0), new vscode.Position(line, originalLine.length));
            deletedRanges.push(range);
            addedRanges.push(range);
        });
        editor.setDecorations(deleteDecoration, deletedRanges);
        editor.setDecorations(addDecoration, addedRanges);
        // Show the changes in a preview panel
        const changesDetail = fixes.map(fix => `Line ${fix.lineNumber}:\n` +
            `Current:  ${fix.originalCode}\n` +
            `Proposed: ${fix.suggestedCode}\n` +
            `Reason: ${fix.explanation}`).join('\n\n');
        const choice = await vscode.window.showInformationMessage('Review the highlighted changes. Would you like to apply these security fixes?', { modal: true, detail: changesDetail }, 'Apply Fixes', 'Cancel');
        return choice === 'Apply Fixes';
    }
    finally {
        // Clean up decorations
        deleteDecoration.dispose();
        addDecoration.dispose();
    }
}
async function activate(context) {
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
        (0, security_1.initializeGemini)(apiKey);
        vscode.window.showInformationMessage('Sentinel initialized successfully.');
    }
    catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error';
        console.error('Failed to initialize Gemini:', errorMessage);
        vscode.window.showErrorMessage(`Failed to initialize Sentinel: ${errorMessage}`);
        return;
    }
    let disposable = vscode.workspace.onDidChangeTextDocument(event => {
        (0, security_1.checkForSecurityIssues)(event.document);
    });
    // Also check when a document is opened
    vscode.workspace.onDidOpenTextDocument(document => {
        (0, security_1.checkForSecurityIssues)(document);
    });
    const diagnosticCollection = vscode.languages.createDiagnosticCollection("sentinel");
    context.subscriptions.push(diagnosticCollection);
    // Register command to suggest fixes
    context.subscriptions.push(vscode.commands.registerCommand('sentinel.suggestFix', async (args) => {
        try {
            const { issue, code, lineNumber, documentUri } = args;
            const document = await vscode.workspace.openTextDocument(vscode.Uri.parse(documentUri));
            // Get context from surrounding lines
            const startLine = Math.max(0, lineNumber - 3);
            const endLine = Math.min(document.lineCount - 1, lineNumber + 3);
            const context = Array.from({ length: endLine - startLine + 1 }, (_, i) => document.lineAt(startLine + i).text).join('\n');
            await vscode.window.withProgress({
                location: vscode.ProgressLocation.Notification,
                title: "Analyzing security issue...",
                cancellable: false
            }, async () => {
                const suggestion = await (0, security_1.suggestSecurityFix)(issue, code, context);
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
                        const range = new vscode.Range(new vscode.Position(line, 0), new vscode.Position(line, lineText.length));
                        // Preserve indentation when applying the fix
                        const suggestedCode = preserveIndentation(originalLine, fix.suggestedCode);
                        edit.replace(document.uri, range, suggestedCode);
                    }
                    await vscode.workspace.applyEdit(edit);
                    vscode.window.showInformationMessage('Security fixes applied successfully!');
                }
            });
        }
        catch (error) {
            vscode.window.showErrorMessage(`Error generating fix: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }));
    context.subscriptions.push(disposable);
    let analyzeDisposable = vscode.commands.registerCommand('sentinel.analyze', () => {
        vscode.window.showInformationMessage('Running Sentinel security analysis...');
    });
    context.subscriptions.push(analyzeDisposable);
}
function createDiffView(fixes) {
    return fixes.map(fix => `Line ${fix.lineNumber}:
\`\`\`diff
- ${fix.originalCode}
+ ${fix.suggestedCode}
\`\`\`
Explanation: ${fix.explanation || ''}`).join('\n\n');
}
function deactivate() { }
//# sourceMappingURL=extension.js.map