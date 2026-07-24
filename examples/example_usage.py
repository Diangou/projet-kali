# examples/example_usage.py
from vuln_scanner.scanner import VulnerabilityScanner
from vuln_scanner.trivy_tool import TrivyTool


def main():
    scanner = VulnerabilityScanner()
    scanner.add_tool(TrivyTool())
    results = scanner.scan('http://example.com')
    print(results)


if __name__ == '__main__':
    main()
