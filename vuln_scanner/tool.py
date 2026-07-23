# vuln_scanner/tool.py
class Tool(object):
    def __init__(self, name):
        self.name = name

    def scan(self, target):
        # Implementation provided by subclasses
        raise NotImplementedError
