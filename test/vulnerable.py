# Test file with various security vulnerabilities

# Dangerous eval with input
user_input = input("Enter some code: ")
eval(user_input)  # Dangerous!

# Hardcoded credentials
password = "super_secret_123"
api_key = "1234-abcd-5678-efgh"

# Dangerous exec
code = "print('Hello')"
exec(code)

# SQL Injection vulnerability
query = "SELECT * FROM users WHERE name = '" + user_input + "'"

# Command injection
import os
os.system("echo " + user_input)

# Unsafe deserialization
import pickle
pickle.loads(user_input)
