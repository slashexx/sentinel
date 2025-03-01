import * as vscode from 'vscode';
import { checkForSecurityIssues } from './security';

export function activate(context: vscode.ExtensionContext) {
    console.log('Sentinel is now active!');

    let disposable = vscode.workspace.onDidChangeTextDocument(event => {
        checkForSecurityIssues(event.document);
    });

    // Also check when a document is opened
    vscode.workspace.onDidOpenTextDocument(document => {
        checkForSecurityIssues(document);
    });

    const diagnosticCollection = vscode.languages.createDiagnosticCollection("sentinel");
    context.subscriptions.push(diagnosticCollection);

    context.subscriptions.push(disposable);
}

export function deactivate() {}
