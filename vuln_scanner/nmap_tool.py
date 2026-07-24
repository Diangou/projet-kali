from __future__ import annotations

import ipaddress
import json
import re
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class NmapService:
    name: str | None = None
    product: str | None = None
    version: str | None = None
    extra_info: str | None = None
    cpe: list[str] = field(default_factory=list)


@dataclass
class NmapPort:
    port: int
    protocol: str
    state: str
    reason: str | None
    service: NmapService
    scripts: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class NmapHost:
    address: str
    address_type: str
    status: str
    hostnames: list[str] = field(default_factory=list)
    ports: list[NmapPort] = field(default_factory=list)


@dataclass
class NmapScanResult:
    tool: str
    target: str
    success: bool
    hosts: list[NmapHost] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class NmapTool:
    name = "nmap"
    executable = "nmap"

    PROFILES: dict[str, list[str]] = {
        "basic": [
            "-sT",
            "--top-ports",
            "100",
        ],
        "services": [
            "-sT",
            "-sV",
            "--version-light",
        ],
        "quick": [
            "-sT",
            "-sV",
            "--version-light",
            "--top-ports",
            "100",
        ],
        "safe": [
            "-sT",
            "-sV",
            "--script",
            "default,safe",
        ],
        "discovery": [
            "-sn",
        ],
    }

    HOSTNAME_PATTERN = re.compile(
        r"^(?=.{1,253}$)"
        r"(?!-)"
        r"[A-Za-z0-9-]{1,63}"
        r"(?<!-)"
        r"(?:\."
        r"(?!-)"
        r"[A-Za-z0-9-]{1,63}"
        r"(?<!-))*"
        r"\.?$"
    )

    def is_available(self) -> bool:
        return shutil.which(self.executable) is not None

    def scan(
        self,
        target: str,
        *,
        profile: str = "services",
        ports: str | list[int] | int | None = None,
        timing: int = 3,
        timeout: int = 600,
        host_timeout: str | None = None,
        max_retries: int = 2,
        skip_discovery: bool = False,
        dns: bool = False,
        allow_network: bool = False,
    ) -> NmapScanResult:
        try:
            normalized_target = self._validate_target(
                target,
                allow_network=allow_network,
            )

            if not self.is_available():
                return NmapScanResult(
                    tool=self.name,
                    target=normalized_target,
                    success=False,
                    errors=[
                        "Nmap est introuvable. Vérifie avec "
                        "`nmap --version`."
                    ],
                )

            validated_timeout = self._validate_timeout(timeout)

            with tempfile.TemporaryDirectory(
                prefix="nmap-framework-"
            ) as temp_dir:
                output_file = Path(temp_dir) / "nmap.xml"

                command = self._build_command(
                    target=normalized_target,
                    output_file=output_file,
                    profile=profile,
                    ports=ports,
                    timing=timing,
                    host_timeout=host_timeout,
                    max_retries=max_retries,
                    skip_discovery=skip_discovery,
                    dns=dns,
                )

                completed = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=validated_timeout,
                    check=False,
                    shell=False,
                )

                hosts = []

                if output_file.exists():
                    hosts = self._parse_xml(output_file)

                errors: list[str] = []

                if completed.returncode != 0:
                    errors.append(
                        completed.stderr.strip()
                        or (
                            "Nmap a terminé avec le code "
                            f"{completed.returncode}."
                        )
                    )

                return NmapScanResult(
                    tool=self.name,
                    target=normalized_target,
                    success=completed.returncode == 0,
                    hosts=hosts,
                    errors=errors,
                    metadata={
                        "profile": profile,
                        "command": command,
                        "return_code": completed.returncode,
                        "stdout": completed.stdout.strip(),
                    },
                )

        except subprocess.TimeoutExpired:
            return NmapScanResult(
                tool=self.name,
                target=target,
                success=False,
                errors=[
                    f"Le scan Nmap a dépassé {timeout} secondes."
                ],
            )
        except (OSError, ValueError, ET.ParseError) as exc:
            return NmapScanResult(
                tool=self.name,
                target=target,
                success=False,
                errors=[str(exc)],
            )

    def _build_command(
        self,
        *,
        target: str,
        output_file: Path,
        profile: str,
        ports: str | list[int] | int | None,
        timing: int,
        host_timeout: str | None,
        max_retries: int,
        skip_discovery: bool,
        dns: bool,
    ) -> list[str]:
        if profile not in self.PROFILES:
            available = ", ".join(sorted(self.PROFILES))

            raise ValueError(
                f"Profil Nmap inconnu : {profile}. "
                f"Profils disponibles : {available}."
            )

        command = [
            self.executable,
            *self.PROFILES[profile],
        ]

        if ports is not None:
            if profile == "discovery":
                raise ValueError(
                    "Les ports ne peuvent pas être utilisés "
                    "avec le profil discovery."
                )

            command.extend(
                [
                    "-p",
                    self._validate_ports(ports),
                ]
            )

        command.append(
            f"-T{self._validate_timing(timing)}"
        )

        if host_timeout is not None:
            command.extend(
                [
                    "--host-timeout",
                    self._validate_duration(host_timeout),
                ]
            )

        if max_retries < 0 or max_retries > 10:
            raise ValueError(
                "max_retries doit être compris entre 0 et 10."
            )

        command.extend(
            [
                "--max-retries",
                str(max_retries),
            ]
        )

        if skip_discovery:
            command.append("-Pn")

        if not dns:
            command.append("-n")

        command.extend(
            [
                "--reason",
                "--noninteractive",
                "--no-stylesheet",
                "-oX",
                str(output_file),
                "--",
                target,
            ]
        )

        return command

    def _parse_xml(
        self,
        xml_path: Path,
    ) -> list[NmapHost]:
        tree = ET.parse(xml_path)
        root = tree.getroot()

        if root.tag != "nmaprun":
            raise ValueError(
                "Le fichier produit n'est pas un rapport Nmap valide."
            )

        hosts: list[NmapHost] = []

        for host_element in root.findall("host"):
            status_element = host_element.find("status")

            status = (
                status_element.attrib.get("state", "unknown")
                if status_element is not None
                else "unknown"
            )

            address_element = self._find_address(host_element)

            address = (
                address_element.attrib.get("addr", "unknown")
                if address_element is not None
                else "unknown"
            )

            address_type = (
                address_element.attrib.get(
                    "addrtype",
                    "unknown",
                )
                if address_element is not None
                else "unknown"
            )

            hostnames = [
                hostname.attrib["name"]
                for hostname in host_element.findall(
                    "./hostnames/hostname"
                )
                if hostname.attrib.get("name")
            ]

            ports: list[NmapPort] = []

            for port_element in host_element.findall(
                "./ports/port"
            ):
                port_number = self._optional_int(
                    port_element.attrib.get("portid")
                )

                if port_number is None:
                    continue

                state_element = port_element.find("state")
                service_element = port_element.find("service")

                state = (
                    state_element.attrib.get(
                        "state",
                        "unknown",
                    )
                    if state_element is not None
                    else "unknown"
                )

                reason = (
                    state_element.attrib.get("reason")
                    if state_element is not None
                    else None
                )

                service = self._parse_service(
                    service_element
                )

                scripts = []

                for script_element in port_element.findall(
                    "script"
                ):
                    scripts.append(
                        {
                            "id": script_element.attrib.get(
                                "id",
                                "unknown",
                            ),
                            "output": script_element.attrib.get(
                                "output",
                                "",
                            ),
                        }
                    )

                ports.append(
                    NmapPort(
                        port=port_number,
                        protocol=port_element.attrib.get(
                            "protocol",
                            "unknown",
                        ),
                        state=state,
                        reason=reason,
                        service=service,
                        scripts=scripts,
                    )
                )

            hosts.append(
                NmapHost(
                    address=address,
                    address_type=address_type,
                    status=status,
                    hostnames=hostnames,
                    ports=ports,
                )
            )

        return hosts

    @staticmethod
    def _find_address(
        host_element: ET.Element,
    ) -> ET.Element | None:
        addresses = host_element.findall("address")

        for address in addresses:
            if address.attrib.get("addrtype") == "ipv4":
                return address

        for address in addresses:
            if address.attrib.get("addrtype") == "ipv6":
                return address

        return addresses[0] if addresses else None

    @staticmethod
    def _parse_service(
        service_element: ET.Element | None,
    ) -> NmapService:
        if service_element is None:
            return NmapService()

        return NmapService(
            name=service_element.attrib.get("name"),
            product=service_element.attrib.get("product"),
            version=service_element.attrib.get("version"),
            extra_info=service_element.attrib.get("extrainfo"),
            cpe=[
                cpe.text
                for cpe in service_element.findall("cpe")
                if cpe.text
            ],
        )

    def _validate_target(
        self,
        target: str,
        *,
        allow_network: bool,
    ) -> str:
        normalized = str(target).strip()

        if not normalized:
            raise ValueError(
                "La cible Nmap ne peut pas être vide."
            )

        if normalized.startswith("-"):
            raise ValueError(
                "La cible ne peut pas commencer par un tiret."
            )

        try:
            return str(
                ipaddress.ip_address(normalized)
            )
        except ValueError:
            pass

        if "/" in normalized:
            try:
                network = ipaddress.ip_network(
                    normalized,
                    strict=False,
                )
            except ValueError as exc:
                raise ValueError(
                    "La plage réseau est invalide."
                ) from exc

            if not allow_network:
                raise ValueError(
                    "Les plages CIDR sont désactivées. "
                    "Active allow_network uniquement pour "
                    "un réseau autorisé."
                )

            if (
                network.version == 4
                and network.prefixlen < 24
            ):
                raise ValueError(
                    "La plage IPv4 est trop large. "
                    "Le minimum autorisé est /24."
                )

            if (
                network.version == 6
                and network.prefixlen < 120
            ):
                raise ValueError(
                    "La plage IPv6 est trop large. "
                    "Le minimum autorisé est /120."
                )

            return str(network)

        if not self.HOSTNAME_PATTERN.fullmatch(normalized):
            raise ValueError(
                "Le nom d'hôte est invalide."
            )

        return normalized.rstrip(".").lower()

    @staticmethod
    def _validate_ports(
        ports: str | list[int] | int,
    ) -> str:
        if isinstance(ports, list):
            value = ",".join(str(port) for port in ports)
        else:
            value = str(ports)

        value = value.strip()

        if not re.fullmatch(r"[0-9,\-]+", value):
            raise ValueError(
                "Format des ports invalide. "
                "Exemples : 80,443 ou 1-1000."
            )

        count = 0

        for entry in value.split(","):
            if not entry:
                raise ValueError(
                    "La liste des ports est invalide."
                )

            if "-" in entry:
                start_text, end_text = entry.split(
                    "-",
                    maxsplit=1,
                )

                start = int(start_text)
                end = int(end_text)

                if start > end:
                    raise ValueError(
                        f"Plage de ports inversée : {entry}."
                    )

                if start < 1 or end > 65535:
                    raise ValueError(
                        f"Plage de ports invalide : {entry}."
                    )

                count += end - start + 1
            else:
                port = int(entry)

                if port < 1 or port > 65535:
                    raise ValueError(
                        f"Port invalide : {port}."
                    )

                count += 1

        if count > 10000:
            raise ValueError(
                "Le scan est limité à 10 000 ports."
            )

        return value

    @staticmethod
    def _validate_timing(timing: int) -> int:
        try:
            value = int(timing)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "Le timing doit être un entier."
            ) from exc

        if value not in {2, 3, 4}:
            raise ValueError(
                "Le timing doit être 2, 3 ou 4."
            )

        return value

    @staticmethod
    def _validate_timeout(timeout: int) -> int:
        try:
            value = int(timeout)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "Le timeout doit être un entier."
            ) from exc

        if value < 10 or value > 7200:
            raise ValueError(
                "Le timeout doit être compris "
                "entre 10 et 7200 secondes."
            )

        return value

    @staticmethod
    def _validate_duration(value: str) -> str:
        normalized = str(value).strip()

        if not re.fullmatch(
            r"[1-9][0-9]*(ms|s|m)",
            normalized,
        ):
            raise ValueError(
                "host_timeout doit ressembler à "
                "500ms, 30s ou 5m."
            )

        return normalized

    @staticmethod
    def _optional_int(
        value: str | None,
    ) -> int | None:
        if value is None:
            return None

        try:
            return int(value)
        except ValueError:
            return None


def save_nmap_result(
    result: NmapScanResult,
    output_path: str | Path,
) -> None:
    path = Path(output_path)
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    path.write_text(
        json.dumps(
            result.to_dict(),
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )