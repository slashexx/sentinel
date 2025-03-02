# Code Vulnerability Checker Setup

## Installation Steps

1. Make sure you have Python 3.7+ installed:
```bash
python --version
```

2. Install all required packages:
```bash
python -m pip install --upgrade pip
python -m pip install transformers torch urllib3 requests huggingface-hub
```

If you still encounter errors, try reinstalling urllib3:
```bash
python -m pip uninstall urllib3
python -m pip install urllib3==1.26.6
```

## Usage

After installing the required packages, run the script:
```bash
```

Or use the interactive mode:
```bash
python code_vulnerability_checker.py --interactive
```

## Usage Examples

1. Scan a file:
```bash
python code_vulnerability_checker.py --file "path/to/your/code.py"
```

2. Check a single line of code:
```bash
python code_vulnerability_checker.py --code "password = 'admin123'"
```

3. Check SQL injection vulnerability:
```bash
python code_vulnerability_checker.py --code "query = 'SELECT * FROM users WHERE id = ' + user_input"
```

4. Interactive Mode Examples:
```bash
python code_vulnerability_checker.py --interactive

# Then enter code samples like:
password = "mysecretpassword123"
TOKEN = "hardcoded_token_12345"
exec(user_input)
eval(untrusted_code)
query = "SELECT * FROM " + table_name
```

The tool will analyze these patterns and report potential security risks with confidence scores.
