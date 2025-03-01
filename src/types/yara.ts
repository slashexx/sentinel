export interface YaraRule {
    name: string;
    strings: YaraString[];
    condition: string;
    metadata?: {
        description?: string;
        severity?: string;
        category?: string;
    };
}

export interface YaraString {
    identifier: string;
    value: string;
    isRegex: boolean;
}
