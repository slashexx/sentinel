import * as fs from 'fs';
import { YaraRule, YaraString } from '../types/yara';

export function parseYaraFile(filePath: string): YaraRule[] {
    console.log(`Attempting to parse YARA file: ${filePath}`);
    const content = fs.readFileSync(filePath, 'utf8');
    console.log('File content:', content);
    
    const rules: YaraRule[] = [];
    const ruleBlocks = content.split(/rule\s+/).filter(block => block.trim());
    console.log(`Found ${ruleBlocks.length} rule blocks`);
    
    for (const block of ruleBlocks) {
        console.log('Parsing rule block:', block);
        const rule = parseRuleBlock(block);
        if (rule) {
            console.log('Successfully parsed rule:', rule);
            rules.push(rule);
        } else {
            console.log('Failed to parse rule block');
        }
    }
    
    return rules;
}

function parseRuleBlock(block: string): YaraRule | null {
    const nameMatch = block.match(/^(\w+)\s*{/);
    if (!nameMatch) {
        console.log('Failed to match rule name');
        return null;
    }

    const name = nameMatch[1];
    console.log('Parsing rule:', name);

    const strings: YaraString[] = [];
    // Fixed regex patterns to better match the YARA format
    const metadataMatch = block.match(/meta:\s*([\s\S]*?)(?=strings:|condition:|$)/);
    const stringsMatch = block.match(/strings:\s*([\s\S]*?)(?=condition:|$)/);
    const conditionMatch = block.match(/condition:\s*([\s\S]*?)(?=}|$)/);

    let metadata = {};
    if (metadataMatch) {
        console.log('Found metadata block:', metadataMatch[1]);
        metadata = parseMetadata(metadataMatch[1]);
    }

    if (stringsMatch) {
        console.log('Found strings block:', stringsMatch[1]);
        strings.push(...parseStrings(stringsMatch[1]));
    }

    const result = {
        name,
        strings,
        condition: conditionMatch ? conditionMatch[1].trim() : 'true',
        metadata
    };
    
    console.log('Parsed rule result:', JSON.stringify(result, null, 2));
    return result;
}

function parseMetadata(metadataBlock: string): Record<string, string> {
    const metadata: Record<string, string> = {};
    const lines = metadataBlock.trim().split('\n');
    
    for (const line of lines) {
        // Fixed regex to better match metadata format
        const match = line.match(/\s*(\w+)\s*=\s*["']([^"']+)["']/);
        if (match) {
            metadata[match[1]] = match[2];
        }
    }
    
    return metadata;
}

function parseStrings(stringsBlock: string): YaraString[] {
    const strings: YaraString[] = [];
    const lines = stringsBlock.trim().split('\n');
    
    for (const line of lines) {
        // Fixed regex to better match string definitions
        const match = line.match(/\s*\$(\w+)\s*=\s*(?:\/(.+)\/|"([^"]+)")/);
        if (match) {
            const identifier = match[1];
            const value = match[2] || match[3]; // match[2] for regex, match[3] for literal strings
            console.log(`Parsed string: ${identifier} = ${value}`);
            strings.push({
                identifier,
                value,
                isRegex: !!match[2] // true if the value was matched as a regex
            });
        }
    }
    
    return strings;
}
