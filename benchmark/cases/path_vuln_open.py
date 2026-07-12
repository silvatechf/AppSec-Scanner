def read_report(filename):
    path = f"/var/reports/{filename}"
    with open(path) as f:
        return f.read()
