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
var path = __toESM(require("path"));

// src/parser/yaraParser.ts
var fs = __toESM(require("fs"));
function parseYaraFile(filePath) {
  console.log(`Attempting to parse YARA file: ${filePath}`);
  const content = fs.readFileSync(filePath, "utf8");
  console.log("File content:", content);
  const rules = [];
  const ruleBlocks = content.split(/rule\s+/).filter((block) => block.trim());
  console.log(`Found ${ruleBlocks.length} rule blocks`);
  for (const block of ruleBlocks) {
    console.log("Parsing rule block:", block);
    const rule = parseRuleBlock(block);
    if (rule) {
      console.log("Successfully parsed rule:", rule);
      rules.push(rule);
    } else {
      console.log("Failed to parse rule block");
    }
  }
  return rules;
}
function parseRuleBlock(block) {
  const nameMatch = block.match(/^(\w+)\s*{/);
  if (!nameMatch) {
    console.log("Failed to match rule name");
    return null;
  }
  const name = nameMatch[1];
  console.log("Parsing rule:", name);
  const strings = [];
  const metadataMatch = block.match(/meta:\s*([\s\S]*?)(?=strings:|condition:|$)/);
  const stringsMatch = block.match(/strings:\s*([\s\S]*?)(?=condition:|$)/);
  const conditionMatch = block.match(/condition:\s*([\s\S]*?)(?=}|$)/);
  let metadata = {};
  if (metadataMatch) {
    console.log("Found metadata block:", metadataMatch[1]);
    metadata = parseMetadata(metadataMatch[1]);
  }
  if (stringsMatch) {
    console.log("Found strings block:", stringsMatch[1]);
    strings.push(...parseStrings(stringsMatch[1]));
  }
  const result = {
    name,
    strings,
    condition: conditionMatch ? conditionMatch[1].trim() : "true",
    metadata
  };
  console.log("Parsed rule result:", JSON.stringify(result, null, 2));
  return result;
}
function parseMetadata(metadataBlock) {
  const metadata = {};
  const lines = metadataBlock.trim().split("\n");
  for (const line of lines) {
    const match = line.match(/\s*(\w+)\s*=\s*["']([^"']+)["']/);
    if (match) {
      metadata[match[1]] = match[2];
    }
  }
  return metadata;
}
function parseStrings(stringsBlock) {
  const strings = [];
  const lines = stringsBlock.trim().split("\n");
  for (const line of lines) {
    const match = line.match(/\s*\$(\w+)\s*=\s*(?:\/(.+)\/|"([^"]+)")/);
    if (match) {
      const identifier = match[1];
      const value = match[2] || match[3];
      console.log(`Parsed string: ${identifier} = ${value}`);
      strings.push({
        identifier,
        value,
        isRegex: !!match[2]
        // true if the value was matched as a regex
      });
    }
  }
  return strings;
}

// src/security.ts
function checkForSecurityIssues(document) {
  const languageId = document.languageId;
  const rulesPath = path.join(__dirname, "..", "rules", `${languageId}.yar`);
  console.log(`Checking document with language: ${languageId}`);
  console.log(`Looking for rules at: ${rulesPath}`);
  let rules = [];
  try {
    rules = parseYaraFile(rulesPath);
    console.log(`Loaded ${rules.length} rules for ${languageId}`);
  } catch (error) {
    console.error(`Error loading YARA rules:`, error);
    return;
  }
  const text = document.getText();
  const diagnostics = [];
  rules.forEach((rule) => {
    console.log(`Applying rule: ${rule.name}`);
    rule.strings.forEach((str) => {
      const regex = str.isRegex ? new RegExp(str.value, "g") : new RegExp(escapeRegExp(str.value), "g");
      console.log(`Checking pattern: ${regex}`);
      let match;
      while ((match = regex.exec(text)) !== null) {
        console.log(`Found match at index ${match.index}:`, match[0]);
        const pos = document.positionAt(match.index);
        const endPos = document.positionAt(match.index + match[0].length);
        diagnostics.push(new vscode.Diagnostic(
          new vscode.Range(pos, endPos),
          `\u26A0\uFE0F ${rule.name}: ${rule.metadata?.description || "Security issue detected"}`,
          rule.metadata?.severity === "high" ? vscode.DiagnosticSeverity.Error : vscode.DiagnosticSeverity.Warning
        ));
      }
    });
  });
  console.log(`Found ${diagnostics.length} issues`);
  const diagnosticCollection = vscode.languages.createDiagnosticCollection("sentinel");
  diagnosticCollection.set(document.uri, diagnostics);
}
function escapeRegExp(string) {
  return string.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
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
