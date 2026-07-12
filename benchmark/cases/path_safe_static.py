def read_config():
    with open("/etc/app/config.yaml") as f:
        return f.read()
