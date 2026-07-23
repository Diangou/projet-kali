# examples/example_usage.py
from vuln_scanner.scanner import VulnerabilityScanner
from vuln_scanner.sqlmap_tool import SqlmapTool


def main():
    scanner = VulnerabilityScanner()
    scanner.add_tool(SqlmapTool())
    results = scanner.scan('http://example.com')
    print(results)


if __name__ == '__main__':
    main()
