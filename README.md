# Sentinel

A VS Code extension for intelligent code analysis and security monitoring.

## Features

- Real-time code analysis for security vulnerabilities
- Custom rule configuration for different programming languages
- Inline security suggestions and fixes
- Security score dashboard for your codebase
- Support for multiple programming languages

## Installation

You can install the extension through the VS Code marketplace or by searching for "Sentinel" in the extensions panel (Ctrl+Shift+X).

## Configuration

Configure Sentinel through VS Code settings:

```json
{
    "sentinel.customRulesPath": "./sentinel-rules.json",
    "sentinel.enableInlineHints": true,
    "sentinel.securityLevel": "high"
}
```

## Usage

Sentinel automatically begins analyzing your code when you open a supported file. Security issues are highlighted inline and detailed information is available in the Problems panel.

## Support

For bug reports and feature requests, please visit our [GitHub repository](https://github.com/your-username/sentinel).

## License

MIT License - see LICENSE file for details.
