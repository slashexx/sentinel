export interface SecurityRule {
    id: string;
    description: string;
    severity: 'high' | 'medium' | 'low';
    detect: (code: string) => Match[];
}

export interface Match {
    line: number;
    match: string;
}

export interface LanguageRules {
    [key: string]: SecurityRule[];
}
