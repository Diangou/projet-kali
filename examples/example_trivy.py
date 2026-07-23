# examples/example_trivy.py
from vuln_scanner.scanner import VulnerabilityScanner
from vuln_scanner.trivy_tool import TrivyTool


def main():
    scanner = VulnerabilityScanner()
    scanner.add_tool(TrivyTool())
    results = scanner.scan('alpine:latest')
    print(results)

    summary = TrivyTool().get_summary('alpine:latest')
    print(summary)


if __name__ == '__main__':
    main()
