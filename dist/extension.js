"use strict";
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/extension.ts
var extension_exports = {};
__export(extension_exports, {
  activate: () => activate,
  deactivate: () => deactivate
});
module.exports = __toCommonJS(extension_exports);
var vscode2 = __toESM(require("vscode"));

// src/security.ts
var vscode = __toESM(require("vscode"));
function checkForSecurityIssues(document) {
  const text = document.getText();
  const diagnostics = [];
  const patterns = [
    { regex: /eval\(/g, message: "\u26A0\uFE0F Avoid using 'eval()', it's a security risk!" },
    { regex: /exec\(/g, message: "\u26A0\uFE0F Using 'exec()' can lead to command injection!" },
    { regex: /password\s*=\s*['"].+['"]/g, message: "\u26A0\uFE0F Hardcoded passwords detected!" }
  ];
  patterns.forEach((pattern) => {
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
  const diagnosticCollection = vscode.languages.createDiagnosticCollection("sentinel");
  diagnosticCollection.set(document.uri, diagnostics);
}

// src/extension.ts
function activate(context) {
  console.log("Sentinel is now active!");
  let disposable = vscode2.workspace.onDidChangeTextDocument((event) => {
    checkForSecurityIssues(event.document);
  });
  vscode2.workspace.onDidOpenTextDocument((document) => {
    checkForSecurityIssues(document);
  });
  const diagnosticCollection = vscode2.languages.createDiagnosticCollection("sentinel");
  context.subscriptions.push(diagnosticCollection);
  context.subscriptions.push(disposable);
}
function deactivate() {
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  activate,
  deactivate
});
//# sourceMappingURL=extension.js.map
