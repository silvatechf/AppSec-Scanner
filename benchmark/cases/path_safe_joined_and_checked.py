import os

def read_report(base_dir, filename):
    resolved = os.path.abspath(os.path.join(base_dir, filename))
    if not resolved.startswith(os.path.abspath(base_dir)):
        raise ValueError("path traversal detected")
    with open("/etc/app/config.yaml") as f:
        return f.read()
