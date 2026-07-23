# vuln_scanner/scanner.py
class VulnerabilityScanner(object):
    def __init__(self):
        self.tools = []

    def scan(self, target):
        results = {}
        for tool in self.tools:
            results[tool.name] = tool.scan(target)
        return results

    def add_tool(self, tool):
        self.tools.append(tool)
