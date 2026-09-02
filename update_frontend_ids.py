import os
import re

directories = ['c:/Users/VICTUS/Desktop/Projects/Internship project/kerubiscan_frontend/kerubiscan/app', 'c:/Users/VICTUS/Desktop/Projects/Internship project/kerubiscan_frontend/kerubiscan/components', 'c:/Users/VICTUS/Desktop/Projects/Internship project/kerubiscan_frontend/kerubiscan/lib']

replacements = [
    (r'id:\s*number', 'id: string'),
    (r'company_id:\s*number', 'company_id: string'),
    (r'asset_id:\s*number', 'asset_id: string'),
]

for root_dir in directories:
    for root, dirs, files in os.walk(root_dir):
        for file in files:
            if file.endswith('.ts') or file.endswith('.tsx'):
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
