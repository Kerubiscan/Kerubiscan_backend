import os
import re

directories = ['src/assets', 'src/audit', 'src/companies', 'src/policies', 'src/reporting', 'src/scans', 'src/scheduling', 'src/secrets', 'src/vulnerabilities']

replacements = [
    (r'asset_id:\s*int', 'asset_id: str'),
    (r'scan_id:\s*int', 'scan_id: str'),
    (r'company_id:\s*int', 'company_id: str'),
    (r'credential_id:\s*int', 'credential_id: str'),
    (r'vuln_id:\s*int', 'vuln_id: str'),
    (r'vulnerability_id:\s*int', 'vulnerability_id: str'),
    (r'id:\s*int', 'id: str'),
]

for root_dir in directories:
    for root, dirs, files in os.walk(root_dir):
        for file in files:
            if file.endswith('.py'):
                path = os.path.join(root, file)
                with open(path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                new_content = content
                for pattern, repl in replacements:
                    new_content = re.sub(pattern, repl, new_content)
                
                if new_content != content:
                    with open(path, 'w', encoding='utf-8') as f:
                        f.write(new_content)
                    print(f"Updated {path}")
