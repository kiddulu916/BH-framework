#!/usr/bin/env python3
"""
Script to fix test settings for all API test files.

This script adds the automatic test settings fixture to all API test classes
to resolve the ALLOWED_HOSTS issue.
"""

import os
import re
from pathlib import Path

def fix_test_file(file_path):
    """Fix test settings in a single test file."""
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Check if the file already has the fixture
    if '@pytest.fixture(autouse=True)' in content:
        print(f"✓ {file_path.name} already has test settings fixture")
        return False
    
    # Find test classes
    class_pattern = r'class\s+(\w+):\s*\n\s*"""([^"]*)"""\s*\n'
    matches = list(re.finditer(class_pattern, content))
    
    if not matches:
        print(f"⚠ {file_path.name} - No test classes found")
        return False
    
    modified = False
    
    for match in matches:
        class_name = match.group(1)
        class_doc = match.group(2)
        
        # Skip if it's not a test class
        if not class_name.startswith('Test'):
            continue
        
        # Find the class definition and add the fixture
        class_start = match.start()
        class_end = content.find('\n', class_start)
        
        # Look for the first test method to insert the fixture before it
        test_method_pattern = r'@pytest\.mark\.asyncio\s*\n\s*async def test_'
        test_match = re.search(test_method_pattern, content[class_end:])
        
        if test_match:
            insert_pos = class_end + test_match.start()
            
            # Create the fixture code
            fixture_code = '''    @pytest.fixture(autouse=True)
    def setup_test_settings(self, override_test_settings):
        """Automatically apply test settings to all tests in this class."""
        pass
    
'''
            
            # Insert the fixture
            content = content[:insert_pos] + fixture_code + content[insert_pos:]
            modified = True
            print(f"✓ {file_path.name} - Added test settings fixture to {class_name}")
    
    if modified:
        # Also add django_db marker to all test methods
        content = re.sub(
            r'@pytest\.mark\.asyncio\s*\n\s*async def test_',
            '@pytest.mark.asyncio\n    @pytest.mark.django_db\n    async def test_',
            content
        )
        
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)
        
        print(f"✓ {file_path.name} - Added django_db markers to test methods")
        return True
    
    return False

def main():
    """Main function to fix all API test files."""
    tests_dir = Path('tests/api')
    
    if not tests_dir.exists():
        print("❌ tests/api directory not found")
        return
    
    test_files = list(tests_dir.glob('test_*.py'))
    
    if not test_files:
        print("❌ No test files found in tests/api")
        return
    
    print(f"Found {len(test_files)} test files to process:")
    
    fixed_count = 0
    for test_file in test_files:
        print(f"\nProcessing {test_file.name}...")
        if fix_test_file(test_file):
            fixed_count += 1
    
    print(f"\n✅ Fixed {fixed_count} out of {len(test_files)} test files")

if __name__ == '__main__':
    main() 