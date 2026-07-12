import os

HEADER = """# ---------------------------------------------------------------------------
# Author: Fernando da Silva Félix | MLOps & AppSec Engineer | 2026
# Project: AppSec Scanner
# ---------------------------------------------------------------------------
"""

def apply_header(directory):
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".py"):
                path = os.path.join(root, file)
                with open(path, "r+", encoding="utf-8") as f:
                    content = f.read()
                    if "Author: Fernando da Silva Félix" not in content:
                        f.seek(0, 0)
                        f.write(HEADER + content)

if __name__ == "__main__":
    apply_header("appsec_scanner")
