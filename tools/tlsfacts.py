#!/usr/bin/env python3
import argparse
import hashlib
import ipaddress
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit, urlunsplit

ROOT = Path(__file__).resolve().parents[1]
INCIDENT_FILE = ROOT / "docs" / "data" / "incident.json"
HASH_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z", re.I)
CERTIFICATE_BLOCK = re.compile(
    rb"-----BEGIN CERTIFICATE-----[\t\r\n]+.*?-----END CERTIFICATE-----",
    re.S,
)


class TargetError(ValueError):
    pass


class Verdict(str, Enum):
    VULNERABLE = "VULNERABLE"
    SAFE = "SAFE"
    UNKNOWN = "UNKNOWN"
    NOT_APPLICABLE = "NOT APPLICABLE"


@dataclass(frozen=True)
class Target:
    url: str


@dataclass(frozen=True)
class CertificateFact:
    index: int
    spki_sha256: Optional[str]
    subject: str
    error: str = ""


@dataclass(frozen=True)
class Finding:
    target: Target
    verdict: Verdict
    detail: str
    certificates: tuple
    curl_status: Optional[int]
    matches: tuple = ()


def parse_target(raw):
    display = raw.strip()
    if not display:
        raise TargetError("provide an HTTPS URL")
    if any(ord(char) <= 32 or ord(char) == 127 for char in display):
        raise TargetError("URL contains whitespace or a control character")
    if display.lower().startswith("http://"):
        raise TargetError("refusing http:// URLs; TLS probes require HTTPS")

    absolute = display if "://" in display else "https://" + display
    try:
        parts = urlsplit(absolute)
        hostname = parts.hostname
    except ValueError as error:
        raise TargetError("URL is malformed") from error
    if parts.scheme.lower() != "https":
        raise TargetError("TLS probes require an https:// URL")
    if not parts.netloc or hostname is None:
        raise TargetError("URL has no hostname")
    if parts.username is not None or parts.password is not None:
        raise TargetError("URL credentials are not supported")
    if parts.fragment:
        raise TargetError("remove the URL fragment before probing")
    if parts.netloc.endswith(":"):
        raise TargetError("URL has an empty port")

    try:
        explicit_port = parts.port
    except ValueError as error:
        raise TargetError("URL has an invalid port") from error
    if explicit_port is not None and not 1 <= explicit_port <= 65535:
        raise TargetError("port must be between 1 and 65535")

    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        try:
            host = hostname.encode("idna").decode("ascii").lower()
        except UnicodeError as error:
            raise TargetError("hostname is invalid") from error
        labels = host.rstrip(".").split(".")
        if len(host) > 253 or not labels or any(not HOST_LABEL.fullmatch(label) for label in labels):
            raise TargetError("hostname is invalid")
    else:
        host = address.compressed

    authority_host = "[" + host + "]" if ":" in host else host
    authority = authority_host
    if explicit_port is not None:
        authority += ":" + str(explicit_port)
    url = urlunsplit(("https", authority, parts.path or "/", parts.query, ""))
    return Target(url=url)


def valid_dns_name(value):
    if not isinstance(value, str) or not value:
        return False
    hostname = value[:-1] if value.endswith(".") else value
    try:
        hostname = hostname.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return False
    labels = hostname.split(".")
    if len(hostname) > 253 or len(labels) < 2:
        return False
    if len(labels) <= 4 and all(label.isdecimal() or label.startswith("0x") for label in labels):
        return False
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        return False
    return all(HOST_LABEL.fullmatch(label) for label in labels)


def load_incident():
    try:
        data = json.loads(INCIDENT_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError("cannot read " + str(INCIDENT_FILE) + ": " + str(error)) from error

    hashes = data.get("spki_sha256") if isinstance(data, dict) else None
    expected_count = data.get("spki_count") if isinstance(data, dict) else None
    incident_hosts = data.get("incident_hosts") if isinstance(data, dict) else None
    if type(expected_count) is not int or expected_count < 1:
        raise ValueError("incident data has an invalid SPKI count")
    if not isinstance(hashes, list) or len(hashes) != expected_count:
        raise ValueError("incident data has an unexpected number of SPKI SHA-256 hashes")
    if any(not isinstance(value, str) or not HASH_PATTERN.fullmatch(value) for value in hashes):
        raise ValueError("incident data contains an invalid SPKI hash")
    if len(set(hashes)) != len(hashes):
        raise ValueError("incident data contains an invalid or duplicate SPKI hash")
    if not isinstance(incident_hosts, list) or not incident_hosts:
        raise ValueError("incident data has no incident hosts")
    if any(not valid_dns_name(host) for host in incident_hosts):
        raise ValueError("incident data contains an invalid incident host")
    return {
        "hashes": frozenset(hashes),
        "incident_hosts": tuple(incident_hosts),
    }


def _openssl(arguments, input_data):
    try:
        result = subprocess.run(
            ["openssl"] + arguments,
            input=input_data,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise ValueError("openssl could not parse the certificate: " + str(error)) from error
    if result.returncode:
        detail = result.stderr.decode("utf-8", "replace").strip()
        raise ValueError(detail or "openssl could not parse the certificate")
    return result.stdout


def certificate_fact(index, pem):
    try:
        public_key = _openssl(["x509", "-inform", "PEM", "-pubkey", "-noout"], pem)
        spki = _openssl(["pkey", "-pubin", "-outform", "DER"], public_key)
        digest = hashlib.sha256(spki).hexdigest()
    except ValueError as error:
        return CertificateFact(index, None, "", str(error))

    try:
        subject_output = _openssl(
            ["x509", "-inform", "PEM", "-noout", "-subject", "-nameopt", "RFC2253"],
            pem,
        ).decode("utf-8", "replace").strip()
        if subject_output.startswith("subject="):
            subject_output = subject_output[len("subject="):]
        subject = subject_output.strip()
    except ValueError:
        subject = ""
    return CertificateFact(index, digest, subject)


def curl_detail(stderr):
    lines = [line.strip() for line in stderr.decode("utf-8", "replace").splitlines() if line.strip()]
    return " ".join(lines[:2])[:240]


def inspect(target, hashes):
    command = [
        "curl",
        "-q",
        "-sS",
        "-o",
        os.devnull,
        "--connect-timeout",
        "10",
        "--max-time",
        "20",
        "--proto",
        "=https",
        "--write-out",
        "%{certs}",
        "--url",
        target.url,
    ]
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=25,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        return Finding(target, Verdict.UNKNOWN, "curl could not complete one TLS transfer: " + str(error), (), None)

    blocks = CERTIFICATE_BLOCK.findall(result.stdout)
    if not blocks:
        detail = curl_detail(result.stderr)
        if result.returncode not in (0, 60):
            reason = "curl transfer failed (exit " + str(result.returncode) + ")"
        elif result.returncode == 60:
            reason = "curl rejected TLS but exposed no certificate PEMs from this transfer; this backend may omit %{certs} for rejected handshakes, so the compromised-key status is UNKNOWN"
        else:
            reason = "curl returned no certificate PEMs from this transfer; use curl 7.88 or newer with a TLS backend that supports %{certs}"
        if detail:
            reason += (": " if result.returncode not in (0, 60) else " (") + detail
            if result.returncode in (0, 60):
                reason += ")"
        return Finding(target, Verdict.UNKNOWN, reason, (), result.returncode)

    certificates = tuple(certificate_fact(index, block + b"\n") for index, block in enumerate(blocks, 1))
    matches = tuple(cert for cert in certificates if cert.spki_sha256 in hashes)
    curl_error = curl_detail(result.stderr)
    if matches and result.returncode == 0:
        detail = "curl accepted a chain containing a compromised SPKI"
        verdict = Verdict.VULNERABLE
    elif matches and result.returncode == 60:
        detail = "curl rejected the same transfer that contained a compromised SPKI"
        verdict = Verdict.SAFE
    elif matches:
        detail = "a compromised SPKI was observed, but curl returned exit " + str(result.returncode)
        verdict = Verdict.UNKNOWN
    elif any(cert.spki_sha256 is None for cert in certificates):
        detail = "at least one served certificate could not be parsed, so the chain may contain an unrecognized compromised key"
        verdict = Verdict.UNKNOWN
    else:
        detail = "the served chain contains no SPKI from the incident list"
        verdict = Verdict.NOT_APPLICABLE

    if curl_error and result.returncode not in (0, 60):
        detail += "; " + curl_error
    return Finding(target, verdict, detail, certificates, result.returncode, matches)


def print_finding(finding):
    print("URL:      " + finding.target.url)
    if finding.certificates:
        print("Chain:    " + str(len(finding.certificates)) + " certificate(s) served")
        matching_indexes = {certificate.index for certificate in finding.matches}
        for certificate in finding.certificates:
            if certificate.spki_sha256 is None:
                detail = certificate.error or "OpenSSL could not parse this certificate"
                print("Chain:    cert " + str(certificate.index) + " could not be parsed: " + detail[:240])
            elif certificate.index in matching_indexes:
                subject = certificate.subject or "certificate subject unavailable"
                print("Chain:    cert " + str(certificate.index) + ": " + subject + " (matches a compromised SPKI hash)")
        if finding.verdict == Verdict.NOT_APPLICABLE:
            print("Chain:    no compromised key in the served chain")
    else:
        print("Chain:    no certificate chain observed from this transfer")

    if finding.curl_status == 0:
        print("Trust:    this client ACCEPTED the chain")
    elif finding.curl_status == 60:
        print("Trust:    this client REJECTED the chain (curl exit 60)")
    elif finding.curl_status is None:
        print("Trust:    no curl result")
    else:
        print("Trust:    no trust decision (curl exit " + str(finding.curl_status) + ")")
    print("VERDICT:  " + finding.verdict.value + " - " + finding.detail)


def exit_code(verdict):
    if verdict == Verdict.VULNERABLE:
        return 1
    if verdict == Verdict.UNKNOWN:
        return 2
    return 0


def check_client(incident):
    findings = []
    for host in incident["incident_hosts"]:
        target = parse_target("https://" + host + "/")
        finding = inspect(target, incident["hashes"])
        findings.append(finding)
        print("{:<60} {:<16} {}".format(host, finding.verdict.value, finding.detail))

    verdicts = tuple(finding.verdict for finding in findings)
    if any(verdict == Verdict.VULNERABLE for verdict in verdicts):
        overall = Verdict.VULNERABLE
        detail = "this client accepted an incident chain containing a compromised key"
    elif verdicts and all(verdict == Verdict.SAFE for verdict in verdicts):
        overall = Verdict.SAFE
        detail = "curl rejected a matched compromised chain from every incident host"
    elif verdicts and all(verdict == Verdict.NOT_APPLICABLE for verdict in verdicts):
        overall = Verdict.NOT_APPLICABLE
        detail = "no incident host served a chain containing a compromised key"
    else:
        overall = Verdict.UNKNOWN
        detail = "the probes did not establish a trust decision for every incident chain"
    print("Result: {} - {}".format(overall.value, detail))
    return exit_code(overall)


def main(argv=None):
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    url_command = commands.add_parser("check-url")
    url_command.add_argument("url")
    commands.add_parser("check-client")
    args = parser.parse_args(argv)

    try:
        incident = load_incident()
    except ValueError as error:
        print("UNKNOWN: " + str(error), file=sys.stderr)
        return 2

    if args.command == "check-client":
        return check_client(incident)
    try:
        target = parse_target(args.url)
    except TargetError as error:
        print("VERDICT: UNKNOWN - " + str(error))
        return 2

    finding = inspect(target, incident["hashes"])
    print_finding(finding)
    return exit_code(finding.verdict)


if __name__ == "__main__":
    sys.exit(main())
