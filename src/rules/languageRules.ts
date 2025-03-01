import { SecurityRule, LanguageRules, Match } from '../types/rules';
import * as fs from 'fs';
import * as path from 'path';

export const languageRules: LanguageRules = {
    'python': [
        {
            id: 'PY_DANGEROUS_EVAL',
            description: "Usage of eval() detected - potential security risk",
            severity: 'high',
            detect: (code: string) => {
                const matches: Match[] = [];
                const lines = code.split('\n');
                lines.forEach((line, index) => {
                    if (line.includes('eval(')) {
                        matches.push({ line: index, match: line.trim() });
                    }
                });
                return matches;
            }
        }
    ]
};

export function getRulesForLanguage(languageId: string): SecurityRule[] {
    return languageRules[languageId] || [];
}
