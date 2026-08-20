#!/usr/bin/env python3
"""Bounded HTTP/3 or HTTPS/TCP probe for the SBX-017 controller."""

from __future__ import annotations

import base64
import importlib.metadata
import ipaddress
import json
import os
import re
import stat
import sys
import time
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


SCOPE_CONFIRMATION = "I_CONTROL_THE_ENDPOINT_AND_AUTHORIZE_BOUNDED_HTTP3_TESTING"
EXPECTED_CURL_CFFI_VERSION = "0.13.0"
TEST_ID = "SBX-017-POC"
TARGET_CASE_ID = "deny-h3-target"
OPERATOR_SECRET_PATH = "/tmp/sbx-017/operator-secret"
ALLOWED_MODES = frozenset(("h3-v3only", "https-v1"))
EXPECTED_CASE_MODES = {
    "allow-h3-control": "h3-v3only",
    "allow-tcp-control": "https-v1",
    "deny-tcp-control": "https-v1",
    "deny-tcp-post-control": "https-v1",
    TARGET_CASE_ID: "h3-v3only",
}
ALLOWED_CONFIGURATION_KEYS = frozenset(
    (
        "scopeConfirmation",
        "endpointUrl",
        "pinnedIPv4",
        "runId",
        "testId",
        "caseId",
        "publicCanary",
        "mode",
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

    pinned_raw = config.get("pinnedIPv4")
    try:
        pinned = ipaddress.IPv4Address(pinned_raw)
    except (ipaddress.AddressValueError, TypeError):
        raise ValueError("pinnedIPv4 must be one exact IPv4 address") from None
    if not pinned.is_global:
        raise ValueError("pinnedIPv4 must be one public controller-pinned address")

    case_id = _identifier(config.get("caseId"), "caseId")
    public_canary = config.get("publicCanary")
    if case_id == TARGET_CASE_ID:
        if "publicCanary" in config:
            raise ValueError("the target case must read its canary from the fixed operator-secret file")
    elif not isinstance(public_canary, str) or CANARY.fullmatch(public_canary) is None:
        raise ValueError("control cases require a bounded publicCanary")
    mode = config.get("mode")
    if mode not in ALLOWED_MODES:
        raise ValueError("mode must be h3-v3only or https-v1")
    if EXPECTED_CASE_MODES.get(case_id) != mode:
        raise ValueError("caseId and mode must match one fixed SBX-017 probe case")

    return {
        "endpointUrl": endpoint_url,
        "hostname": parsed.hostname.encode("idna").decode("ascii").lower(),
        "pinnedIPv4": str(pinned),
        "runId": _identifier(config.get("runId"), "runId"),
        "testId": TEST_ID,
        "caseId": case_id,
        "canarySource": "operator-secret-file" if case_id == TARGET_CASE_ID else "controller-public-canary",
        **({"publicCanary": public_canary} if case_id != TARGET_CASE_ID else {}),
        "mode": mode,
        "timeoutSeconds": _bounded_integer(
            config.get("timeoutSeconds"), "timeoutSeconds", 1, 20, 8
        ),
        "maxResponseBytes": _bounded_integer(
            config.get("maxResponseBytes"), "maxResponseBytes", 128, 4096, 1024
        ),
    }


def build_request_url(config: dict[str, Any], request_canary: str) -> str:
    parsed = urlsplit(config["endpointUrl"])
    query = list(parse_qsl(parsed.query, keep_blank_values=True))
    query.extend(
        (
            ("run", config["runId"]),
            ("case", config["caseId"]),
            ("canary", request_canary),
        )
    )
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", urlencode(query), ""))


def plan(config: dict[str, Any]) -> dict[str, Any]:
    return {
        "ok": True,
        "mode": "plan",
        "probeMode": config["mode"],
        "canarySource": config["canarySource"],
        "endpointUrl": config["endpointUrl"],
        "hostname": config["hostname"],
        "pinnedIPv4": config["pinnedIPv4"],
        "port": 443,
        "method": "GET",
        "requestedHttpVersion": "v3only" if config["mode"] == "h3-v3only" else "v1",
        "fallbackAllowed": False,
        "tlsVerificationRequired": True,
        "redirectsAllowed": False,
        "environmentProxyTrust": False,
        "proxyOptionForcedEmpty": True,
        "noProxyOption": "*",
        "dnsPinnedWithCurlResolve": True,
        "maximumRequests": 1,
        "maximumResponseBytes": config["maxResponseBytes"],
        "maximumReceiveChunkBytes": 1024,
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
                raise ValueError("operator-secret file has invalid type or size")
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


def _elapsed_milliseconds(value: Any) -> int | None:
    try:
        if hasattr(value, "total_seconds"):
            return round(float(value.total_seconds()) * 1000)
        return round(float(value) * 1000)
    except (TypeError, ValueError):
        return None


def execute(config: dict[str, Any]) -> dict[str, Any]:
    # Imports are deferred so --plan remains a standard-library-only operation.
    from curl_cffi import CurlHttpVersion, CurlOpt
    from curl_cffi.curl import CURL_WRITEFUNC_ERROR
    from curl_cffi.requests import Session
    from curl_cffi.requests.exceptions import RequestException

    dependency_version = importlib.metadata.version("curl_cffi")
    if dependency_version != EXPECTED_CURL_CFFI_VERSION:
        raise RuntimeError(
            f"curl_cffi version must be exactly {EXPECTED_CURL_CFFI_VERSION}"
        )

    requested_version = "v3only" if config["mode"] == "h3-v3only" else "v1"
    request_canary = (
        read_operator_secret()
        if config["canarySource"] == "operator-secret-file"
        else config["publicCanary"]
    )
    request_url = build_request_url(config, request_canary)
    resolve_entry = f"{config['hostname']}:443:{config['pinnedIPv4']}"
    started = time.monotonic()
    common = {
        "runId": config["runId"],
        "testId": config["testId"],
        "caseId": config["caseId"],
        "probeMode": config["mode"],
        "canarySource": config["canarySource"],
        "requestedHttpVersion": requested_version,
        "fallbackAllowed": False,
        "endpointHostname": config["hostname"],
        "pinnedIPv4": config["pinnedIPv4"],
        "pinnedPort": 443,
        "tlsVerificationRequired": True,
        "redirectsAllowed": False,
        "environmentProxyTrust": False,
        "proxyOptionForcedEmpty": True,
        "noProxyOption": "*",
        "dnsPinnedWithCurlResolve": True,
        "curlCffiVersion": dependency_version,
    }
    session_options = {
        "trust_env": False,
        "verify": True,
        "allow_redirects": False,
        "max_redirects": 0,
        "timeout": config["timeoutSeconds"],
        "http_version": requested_version,
        "default_headers": False,
        "discard_cookies": True,
        "curl_options": {
            CurlOpt.RESOLVE: [resolve_entry],
            CurlOpt.PROXY: "",
            CurlOpt.NOPROXY: "*",
            CurlOpt.BUFFERSIZE: 1024,
        },
    }

    body_chunks: list[bytes] = []
    received_body_bytes = 0
    response_too_large = False

    def receive_body(chunk: bytes) -> int:
        """Retain at most maxResponseBytes and abort on the first oversized chunk."""
        nonlocal received_body_bytes, response_too_large
        received_body_bytes += len(chunk)
        remaining = max(0, config["maxResponseBytes"] - sum(map(len, body_chunks)))
        if remaining:
            body_chunks.append(bytes(chunk[:remaining]))
        if received_body_bytes > config["maxResponseBytes"]:
            response_too_large = True
            return CURL_WRITEFUNC_ERROR
        return len(chunk)

    try:
        with Session(**session_options) as session:
            response = session.get(
                request_url,
                headers={
                    "accept": "application/json",
                    "user-agent": "vsc-sbx-017/1",
                },
                accept_encoding=None,
                allow_redirects=False,
                max_redirects=0,
                verify=True,
                quote=False,
                content_callback=receive_body,
            )
        body = b"".join(body_chunks)
        response_metadata = {
            "statusCode": int(response.status_code),
            "actualHttpVersion": int(response.http_version),
            "primaryIp": response.primary_ip,
            "primaryPort": int(response.primary_port),
            "redirectCount": int(response.redirect_count),
            "contentType": str(response.headers.get("content-type", ""))[:128],
            "cacheControl": str(response.headers.get("cache-control", ""))[:128],
            "bodyByteLength": len(body),
            "elapsedMs": _elapsed_milliseconds(response.elapsed),
        }
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
        operation_id_valid_shape = (
            isinstance(operation_id, str) and OPERATION_ID.fullmatch(operation_id) is not None
        )
        return {
            **common,
            "ok": True,
            "phase": "response",
            "tlsVerifiedByClient": True,
            "response": response_metadata,
            "operationId": operation_id if operation_id_valid_shape else None,
            "operationIdShapeValid": operation_id_valid_shape,
            "authorized": authorized,
            "expectedHttp3ResponseVersion": int(CurlHttpVersion.V3),
            "durationMs": round((time.monotonic() - started) * 1000),
        }
    except RequestException as error:
        response = getattr(error, "response", None)
        if response_too_large:
            return {
                **common,
                "ok": False,
                "phase": "response-validation",
                "errorCode": "RESPONSE_TOO_LARGE",
                "receivedBodyByteLength": received_body_bytes,
                "retainedBodyByteLength": sum(map(len, body_chunks)),
                "maximumResponseBytes": config["maxResponseBytes"],
                "curlErrorCode": int(getattr(error, "code", 0)),
                "responseStatusCode": int(getattr(response, "status_code", 0) or 0),
                "actualHttpVersion": int(getattr(response, "http_version", 0) or 0),
                "primaryIp": str(getattr(response, "primary_ip", "") or ""),
                "primaryPort": int(getattr(response, "primary_port", 0) or 0),
                "durationMs": round((time.monotonic() - started) * 1000),
            }
        return {
            **common,
            "ok": False,
            "phase": "request",
            "errorType": type(error).__name__,
            "curlErrorCode": int(getattr(error, "code", 0)),
            "responseStatusCode": int(getattr(response, "status_code", 0) or 0),
            "actualHttpVersion": int(getattr(response, "http_version", 0) or 0),
            "primaryIp": str(getattr(response, "primary_ip", "") or ""),
            "primaryPort": int(getattr(response, "primary_port", 0) or 0),
            "durationMs": round((time.monotonic() - started) * 1000),
        }


def decode_configuration(encoded: str) -> dict[str, Any]:
    padding = "=" * (-len(encoded) % 4)
    try:
        decoded = base64.urlsafe_b64decode(encoded + padding)
        return validate_configuration(json.loads(decoded.decode("utf-8")))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("invalid base64url JSON configuration") from error


def main() -> None:
    if len(sys.argv) < 2:
        raise ValueError("missing base64url SBX-017 probe configuration")
    config = decode_configuration(sys.argv[1])
    result = plan(config) if len(sys.argv) > 2 and sys.argv[2] == "--plan" else execute(config)
    sys.stdout.write(json.dumps(result, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:  # Emit a bounded machine-readable failure, never a traceback.
        sys.stdout.write(
            json.dumps(
                {
                    "ok": False,
                    "phase": "configuration",
                    "errorType": type(error).__name__,
                    "error": str(error).replace("\x00", "").replace("\r", " ").replace("\n", " ")[:256],
                },
                separators=(",", ":"),
            )
            + "\n"
        )
        raise SystemExit(2)
