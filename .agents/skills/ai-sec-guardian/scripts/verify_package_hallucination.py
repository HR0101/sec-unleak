#!/usr/bin/env python3
"""
verify_package_hallucination.py
Mitigate No.080: Slop Squatting / AI Package Hallucination
Verifies whether a package name proposed by an LLM actually exists on npm or PyPI.
"""

import sys
import json
import urllib.request
import urllib.error

def check_pypi(package_name: str) -> bool:
    url = f"https://pypi.org/pypi/{package_name}/json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "sec-unleak-verifier/1.0"})
        with urllib.request.urlopen(req, timeout=5) as response:
            return response.status == 200
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return False
        return False
    except Exception:
        return False

def check_npm(package_name: str) -> bool:
    url = f"https://registry.npmjs.org/{package_name}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "sec-unleak-verifier/1.0"})
        with urllib.request.urlopen(req, timeout=5) as response:
            return response.status == 200
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return False
        return False
    except Exception:
        return False

def main():
    if len(sys.argv) < 3:
        print("Usage: verify_package_hallucination.py <ecosystem: npm|pypi> <package_name_1> [package_name_2 ...]")
        sys.exit(1)

    ecosystem = sys.argv[1].lower()
    packages = sys.argv[2:]

    results = {}
    for pkg in packages:
        if ecosystem == "npm":
            exists = check_npm(pkg)
        elif ecosystem in ("pypi", "python"):
            exists = check_pypi(pkg)
        else:
            print(f"Unknown ecosystem: {ecosystem}. Choose npm or pypi.")
            sys.exit(1)

        results[pkg] = {
            "exists": exists,
            "status": "LEGITIMATE / FOUND" if exists else "[WARN] DANGER: NOT FOUND (Potential AI Hallucination / Slop Squatting!)"
        }

    print(json.dumps(results, indent=2, ensure_ascii=False))

    # Exit 1 if any package not found
    if any(not r["exists"] for r in results.values()):
        sys.exit(1)
    sys.exit(0)

if __name__ == "__main__":
    main()
