# vuln_scanner/utils/mapper.py
from .models import Vulnerability
from .severity import normalize


def trivy_to_vulnerabilities(raw, target=None):
    """raw = the dict returned by TrivyTool.scan()."""
    vulnerabilities = []

    if not isinstance(raw, dict) or 'Results' not in raw:
        return vulnerabilities

    for result in raw.get('Results') or []:
        pkg_target = result.get('Target', target)

        for v in result.get('Vulnerabilities') or []:
            vulnerabilities.append(Vulnerability(
                tool='trivy',
                id=v.get('VulnerabilityID'),
                title=v.get('Title') or v.get('VulnerabilityID'),
                description=v.get('Description'),
                severity=normalize(v.get('Severity')),
                target=pkg_target,
                location=v.get('PkgName'),
                cve=v.get('VulnerabilityID'),
                cvss=(v.get('CVSS') or {}).get('nvd', {}).get('V3Score'),
                recommendation=(
                    f"Upgrade to {v['FixedVersion']}"
                    if v.get('FixedVersion') else None
                ),
                references=v.get('References') or [],
                raw=v,
            ))

    return vulnerabilities


def nmap_to_vulnerabilities(scan_result, target=None):
    """scan_result = the NmapScanResult returned by NmapTool.scan().

    `target` is accepted but unused — NmapScanResult already carries the
    scanned host per-port — kept only so every mapper shares one call
    signature (mapper(raw_result, target=target)).
    """
    vulnerabilities = []

    for host in getattr(scan_result, 'hosts', []) or []:
        for port in getattr(host, 'ports', []) or []:
            if port.state != 'open':
                continue

            service_name = port.service.name or 'unknown'
            title = f'Port {port.port}/{port.protocol} open ({service_name})'
            product = ' '.join(
                p for p in [port.service.product, port.service.version] if p
            )

            vulnerabilities.append(Vulnerability(
                tool='nmap',
                id=None,
                title=title,
                description=product or None,
                severity=normalize('info'),
                target=host.address,
                location=f'{host.address}:{port.port}',
                cve=None,
                cvss=None,
                recommendation=(
                    'Close or firewall this port if the service is not '
                    'required.'
                ),
                references=[],
                raw={
                    'port': port.port,
                    'protocol': port.protocol,
                    'service': service_name,
                    'product': product,
                },
            ))

    return vulnerabilities


def semgrep_to_vulnerabilities(raw, target=None):
    """raw = parsed JSON from `semgrep --json`."""
    vulnerabilities = []

    if not isinstance(raw, dict):
        return vulnerabilities

    for result in raw.get('results') or []:
        extra = result.get('extra') or {}
        metadata = extra.get('metadata') or {}
        path = result.get('path')
        line = (result.get('start') or {}).get('line')

        vulnerabilities.append(Vulnerability(
            tool='semgrep',
            id=result.get('check_id'),
            title=extra.get('message', result.get('check_id', 'Semgrep finding')),
            description=metadata.get('description'),
            severity=normalize(extra.get('severity')),
            target=target or path,
            location=f'{path}:{line}' if path and line else path,
            cve=None,
            cvss=None,
            recommendation=extra.get('fix'),
            references=metadata.get('references') or [],
            raw=result,
        ))

    return vulnerabilities


def nuclei_to_vulnerabilities(findings, target=None):
    """findings = list of parsed nuclei -jsonl records.

    `target` is accepted but unused — each finding already carries its own
    `host` — kept only for a uniform mapper(raw_result, target=target) call
    signature across tools.
    """
    vulnerabilities = []

    for finding in findings or []:
        info = finding.get('info') or {}
        classification = info.get('classification') or {}
        cve_ids = classification.get('cve-id') or []

        vulnerabilities.append(Vulnerability(
            tool='nuclei',
            id=finding.get('template-id'),
            title=info.get('name', finding.get('template-id', 'Nuclei finding')),
            description=info.get('description'),
            severity=normalize(info.get('severity')),
            target=finding.get('host'),
            location=finding.get('matched-at') or finding.get('host'),
            cve=cve_ids[0] if cve_ids else None,
            cvss=(info.get('classification') or {}).get('cvss-score'),
            recommendation=info.get('remediation'),
            references=info.get('reference') or [],
            raw=finding,
        ))

    return vulnerabilities


MAPPERS = {
    'trivy': trivy_to_vulnerabilities,
    'nmap': nmap_to_vulnerabilities,
    'semgrep': semgrep_to_vulnerabilities,
    'nuclei': nuclei_to_vulnerabilities,
}
