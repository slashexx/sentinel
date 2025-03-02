export interface CodeFix {
    lineNumber: number;
    originalCode: string;
    suggestedCode: string;
    explanation?: string;
}

export interface GeminiResponse {
    fixes: CodeFix[];
    overallExplanation?: string;
}
