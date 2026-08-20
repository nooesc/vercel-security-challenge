#!/usr/bin/env python3
"""One-request HTTPS probe for the bounded SBX-021 CIDR-precedence packet."""

from __future__ import annotations

import base64
import hashlib
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import stat
import sys
import time
from typing import Any
from urllib.parse import urlencode, urlsplit


SCOPE_CONFIRMATION = "I_CONTROL_THE_ENDPOINT_AND_AUTHORIZE_BOUNDED_CIDR_PRECEDENCE_TESTING"
TEST_ID = "SBX-021-POC"
TARGET_CASE_ID = "restricted-target-secret"
OPERATOR_SECRET_PATH = "/tmp/sbx-021/operator-secret"
CONTROL_CASES = frozenset(("baseline-target-allow", "restricted-safe-control"))
ALLOWED_CASES = CONTROL_CASES | frozenset((TARGET_CASE_ID,))
ALLOWED_CONFIGURATION_KEYS = frozenset(
    (
        "scopeConfirmation",
        "endpointUrl",
        "pinnedIPv4",
        "runId",
        "testId",
        "caseId",
        "publicCanary",
        "timeoutSeconds",
        "maxResponseBytes",
    )
)
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
CANARY = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
OPERATION_ID = re.compile(r"^h3_[A-Za-z0-9_-]{43}$")


def _record(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{field} must be an object")
    return value


def _identifier(value: Any, field: str) -> str:
    if not isinstance(value, str) or IDENTIFIER.fullmatch(value) is None:
        raise ValueError(f"{field} must be a bounded identifier")
    return value


def _bounded_integer(
    value: Any,
    field: str,
    minimum: int,
    maximum: int,
    fallback: int,
) -> int:
    selected = fallback if value is None else value
    if isinstance(selected, bool) or not isinstance(selected, int):
        raise ValueError(f"{field} must be an integer")
    if selected < minimum or selected > maximum:
        raise ValueError(f"{field} must be from {minimum} through {maximum}")
    return selected


def validate_configuration(value: Any) -> dict[str, Any]:
    config = _record(value, "configuration")
    unknown = sorted(set(config) - ALLOWED_CONFIGURATION_KEYS)
    if unknown:
        raise ValueError(f"configuration field {json.dumps(unknown[0])} is not allowed")
    if config.get("scopeConfirmation") != SCOPE_CONFIRMATION:
        raise ValueError(f"scopeConfirmation must equal {json.dumps(SCOPE_CONFIRMATION)}")
    if config.get("testId") != TEST_ID:
        raise ValueError(f"testId must equal {json.dumps(TEST_ID)}")

    endpoint_url = config.get("endpointUrl")
    if not isinstance(endpoint_url, str) or endpoint_url.strip() != endpoint_url:
        raise ValueError("endpointUrl must be a canonical HTTPS URL")
    parsed = urlsplit(endpoint_url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.port not in (None, 443)
        or parsed.path != "/v1/h3-action"
    ):
        raise ValueError(
            "endpointUrl must be HTTPS on port 443 at /v1/h3-action without credentials, query, or fragment"
        )
    try:
        ipaddress.ip_address(parsed.hostname)
    except ValueError:
        pass
    else:
        raise ValueError("endpointUrl must use a DNS hostname so TLS identity remains verifiable")
    if any(character.isspace() or ord(character) < 0x20 for character in endpoint_url):
        raise ValueError("endpointUrl contains forbidden whitespace or control characters")

    try:
        pinned = ipaddress.IPv4Address(config.get("pinnedIPv4"))
    except (ipaddress.AddressValueError, TypeError):
        raise ValueError("pinnedIPv4 must be one exact IPv4 address") from None
    if not pinned.is_global:
        raise ValueError("pinnedIPv4 must be one public controller-pinned address")

    case_id = _identifier(config.get("caseId"), "caseId")
    if case_id not in ALLOWED_CASES:
        raise ValueError("caseId is not one fixed SBX-021 probe case")
    public_canary = config.get("publicCanary")
    if case_id == TARGET_CASE_ID:
        if "publicCanary" in config:
            raise ValueError("the target case must read its canary from the fixed operator-secret file")
    elif not isinstance(public_canary, str) or CANARY.fullmatch(public_canary) is None:
        raise ValueError("control cases require a bounded publicCanary")

    return {
        "endpointUrl": endpoint_url,
        "hostname": parsed.hostname.encode("idna").decode("ascii").lower(),
        "pinnedIPv4": str(pinned),
        "runId": _identifier(config.get("runId"), "runId"),
        "testId": TEST_ID,
        "caseId": case_id,
        "canarySource": (
            "operator-secret-file" if case_id == TARGET_CASE_ID else "controller-public-canary"
        ),
        **({"publicCanary": public_canary} if case_id != TARGET_CASE_ID else {}),
        "timeoutSeconds": _bounded_integer(
            config.get("timeoutSeconds"), "timeoutSeconds", 1, 20, 8
        ),
        "maxResponseBytes": _bounded_integer(
            config.get("maxResponseBytes"), "maxResponseBytes", 128, 4096, 1024
        ),
    }


def read_operator_secret() -> str:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(OPERATOR_SECRET_PATH, flags)
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_mode & 0o077
                or metadata.st_size < 16
                or metadata.st_size > 128
            ):
                raise ValueError("operator-secret file has invalid type, mode, or size")
            raw = os.read(descriptor, 129)
            if len(raw) != metadata.st_size:
                raise ValueError("operator-secret file changed while it was read")
        finally:
            os.close(descriptor)
    except OSError as error:
        raise ValueError("operator-secret file could not be read safely") from error
    try:
        secret = raw.decode("ascii")
    except UnicodeDecodeError as error:
        raise ValueError("operator-secret file is not a bounded base64url value") from error
    if CANARY.fullmatch(secret) is None:
        raise ValueError("operator-secret file is not a bounded base64url value")
    return secret


def build_request_target(config: dict[str, Any], canary: str) -> str:
    query = urlencode(
        (("run", config["runId"]), ("case", config["caseId"]), ("canary", canary))
    )
    return f"/v1/h3-action?{query}"


def plan(config: dict[str, Any]) -> dict[str, Any]:
    return {
        "ok": True,
        "mode": "plan",
        "testId": TEST_ID,
        "caseId": config["caseId"],
        "canarySource": config["canarySource"],
        "endpointHostname": config["hostname"],
        "pinnedIPv4": config["pinnedIPv4"],
        "pinnedPort": 443,
        "protocol": "https-http1.1",
        "tlsVerificationRequired": True,
        "sniEqualsEndpointHostname": True,
        "dnsLookupUsedForConnection": False,
        "redirectsAllowed": False,
        "environmentProxyTrust": False,
        "maximumRequests": 1,
        "maximumResponseBytes": config["maxResponseBytes"],
        "secretBearingRequestMaterialRetention": (
            "none" if config["caseId"] == TARGET_CASE_ID else "not-applicable"
        ),
        "operatorSecretPath": OPERATOR_SECRET_PATH if config["caseId"] == TARGET_CASE_ID else None,
    }


def _common(config: dict[str, Any]) -> dict[str, Any]:
    return {
        "runId": config["runId"],
        "testId": TEST_ID,
        "caseId": config["caseId"],
        "canarySource": config["canarySource"],
        "endpointHostname": config["hostname"],
        "pinnedIPv4": config["pinnedIPv4"],
        "pinnedPort": 443,
        "protocol": "https-http1.1",
        "tlsVerificationRequired": True,
        "sniEqualsEndpointHostname": True,
        "dnsLookupUsedForConnection": False,
        "redirectsAllowed": False,
        "environmentProxyTrust": False,
        "secretBearingRequestMaterialRetention": (
            "none" if config["caseId"] == TARGET_CASE_ID else "not-applicable"
        ),
    }


def execute(config: dict[str, Any]) -> dict[str, Any]:
    canary = (
        read_operator_secret()
        if config["canarySource"] == "operator-secret-file"
        else config["publicCanary"]
    )
    target = build_request_target(config, canary)
    target_sha256 = (
        None
        if config["canarySource"] == "operator-secret-file"
        else hashlib.sha256(target.encode("ascii")).hexdigest()
    )
    started = time.monotonic()
    common = _common(config)
    phase = "connect"
    raw_socket: socket.socket | None = None
    tls_socket: ssl.SSLSocket | None = None
    try:
        raw_socket = socket.create_connection(
            (config["pinnedIPv4"], 443), timeout=config["timeoutSeconds"]
        )
        raw_socket.settimeout(config["timeoutSeconds"])
        phase = "tls"
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.set_alpn_protocols(["http/1.1"])
        tls_socket = context.wrap_socket(raw_socket, server_hostname=config["hostname"])
        raw_socket = None
        peer_certificate = tls_socket.getpeercert(binary_form=True)
        remote_ip, remote_port = tls_socket.getpeername()[:2]
        if remote_ip != config["pinnedIPv4"] or remote_port != 443:
            raise RuntimeError("verified TLS socket did not use the controller-pinned endpoint")
        if tls_socket.selected_alpn_protocol() != "http/1.1":
            raise RuntimeError("endpoint did not negotiate the fixed HTTP/1.1 protocol")

        phase = "request"
        request = (
            f"GET {target} HTTP/1.1\r\n"
            f"Host: {config['hostname']}\r\n"
            "Accept: application/json\r\n"
            "Accept-Encoding: identity\r\n"
            "User-Agent: vsc-sbx-021/1\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        tls_socket.sendall(request)
        response = http.client.HTTPResponse(tls_socket, method="GET")
        response.begin()
        body = response.read(config["maxResponseBytes"] + 1)
        if len(body) > config["maxResponseBytes"]:
            raise RuntimeError("response body exceeded maxResponseBytes")
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            payload = None
        authorized = (
            isinstance(payload, dict)
            and set(payload) == {"authorized", "operationId"}
            and payload.get("authorized") is True
        )
        operation_id = payload.get("operationId") if authorized else None
        operation_id_valid = (
            isinstance(operation_id, str) and OPERATION_ID.fullmatch(operation_id) is not None
        )
        return {
            **common,
            "ok": True,
            "phase": "response",
            "tlsVerifiedByClient": True,
            "tlsVersion": tls_socket.version(),
            "tlsCipher": tls_socket.cipher()[0] if tls_socket.cipher() else None,
            "selectedAlpn": tls_socket.selected_alpn_protocol(),
            "peerCertificateSha256": hashlib.sha256(peer_certificate).hexdigest(),
            "remoteIp": remote_ip,
            "remotePort": remote_port,
            **({"requestTargetSha256": target_sha256} if target_sha256 is not None else {}),
            "response": {
                "statusCode": response.status,
                "httpVersion": response.version,
                "contentType": str(response.getheader("content-type", ""))[:128],
                "cacheControl": str(response.getheader("cache-control", ""))[:128],
                "bodyByteLength": len(body),
            },
            "authorized": authorized,
            "operationId": operation_id if operation_id_valid else None,
            "operationIdShapeValid": operation_id_valid,
            "durationMs": round((time.monotonic() - started) * 1000),
        }
    except Exception as error:
        error_number = getattr(error, "errno", None)
        return {
            **common,
            "ok": False,
            "phase": phase,
            "errorType": type(error).__name__,
            "errorNumber": error_number if isinstance(error_number, int) else None,
            "responseStatusCode": 0,
            "operationId": None,
            **({"requestTargetSha256": target_sha256} if target_sha256 is not None else {}),
            "durationMs": round((time.monotonic() - started) * 1000),
        }
    finally:
        if tls_socket is not None:
            tls_socket.close()
        elif raw_socket is not None:
            raw_socket.close()


def decode_configuration(encoded: str) -> dict[str, Any]:
    padding = "=" * (-len(encoded) % 4)
    try:
        decoded = base64.urlsafe_b64decode(encoded + padding)
        return validate_configuration(json.loads(decoded.decode("utf-8")))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("invalid base64url JSON configuration") from error


def main() -> None:
    if len(sys.argv) < 2:
        raise ValueError("missing base64url SBX-021 probe configuration")
    config = decode_configuration(sys.argv[1])
    result = plan(config) if len(sys.argv) > 2 and sys.argv[2] == "--plan" else execute(config)
    sys.stdout.write(json.dumps(result, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        sys.stdout.write(
            json.dumps(
                {
                    "ok": False,
                    "phase": "configuration",
                    "errorType": type(error).__name__,
                    "error": str(error)
                    .replace("\x00", "")
                    .replace("\r", " ")
                    .replace("\n", " ")[:256],
                },
                separators=(",", ":"),
            )
            + "\n"
        )
        raise SystemExit(2)
