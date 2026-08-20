#!/usr/bin/env python3
"""One-request ECH/plain HTTPS probe for the bounded SBX-031 controller."""

from __future__ import annotations

import base64
import hashlib
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


SCOPE_CONFIRMATION = "I_CONTROL_THE_ENDPOINT_AND_AUTHORIZE_BOUNDED_ECH_TESTING"
EXPECTED_CURL_CFFI_VERSION = "0.13.0"
TEST_ID = "SBX-031-POC"
TARGET_CASE_ID = "restricted-ech-target"
OPERATOR_SECRET_PATH = "/tmp/sbx-031/operator-secret"
CURLINFO_SSL_DATA_OUT = 6
TLS_CONTENT_TYPE_HANDSHAKE = 22
TLS_HANDSHAKE_CLIENT_HELLO = 1
ECH_EXTENSION_TYPE = 0xFE0D
MAX_TLS_RECORD_PAYLOAD_BYTES = 18_432
MAX_SSL_DATA_OUT_EVENTS = 64
EXPECTED_CASE_MODES = {
    "allow-plain-control": "plain",
    "allow-ech-control": "ech",
    "restricted-plain-negative": "plain",
    TARGET_CASE_ID: "ech",
}
ALLOWED_CONFIGURATION_KEYS = frozenset(
    (
        "scopeConfirmation",
        "endpointUrl",
        "pinnedIPv4",
        "echConfigListBase64",
        "echPublicName",
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
DNS_NAME = re.compile(
    r"^(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)


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


def _dns_name(value: Any, field: str) -> str:
    if not isinstance(value, str) or value != value.strip():
        raise ValueError(f"{field} must be a canonical DNS hostname")
    try:
        name = value.encode("idna").decode("ascii").lower()
    except UnicodeError as error:
        raise ValueError(f"{field} must be a canonical DNS hostname") from error
    if DNS_NAME.fullmatch(name) is None:
        raise ValueError(f"{field} must be a canonical DNS hostname")
    return name


def parse_ech_config_list(encoded: Any) -> tuple[bytes, str]:
    if not isinstance(encoded, str) or len(encoded) < 16 or len(encoded) > 4096:
        raise ValueError("echConfigListBase64 must be a bounded base64 value")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, base64.binascii.Error) as error:
        raise ValueError("echConfigListBase64 is not canonical base64") from error
    if base64.b64encode(raw).decode("ascii") != encoded:
        raise ValueError("echConfigListBase64 is not canonical base64")
    if len(raw) < 6 or len(raw) > 2048 or int.from_bytes(raw[0:2], "big") != len(raw) - 2:
        raise ValueError("ECHConfigList length is invalid")

    position = 2
    public_names: set[str] = set()
    while position < len(raw):
        if position + 4 > len(raw):
            raise ValueError("ECHConfig header is truncated")
        version = int.from_bytes(raw[position : position + 2], "big")
        contents_length = int.from_bytes(raw[position + 2 : position + 4], "big")
        position += 4
        end = position + contents_length
        if version != 0xFE0D or end > len(raw):
            raise ValueError("ECHConfig version or length is unsupported")

        cursor = position
        if cursor + 5 > end:
            raise ValueError("ECHConfig contents are truncated")
        cursor += 3  # config_id plus kem_id
        public_key_length = int.from_bytes(raw[cursor : cursor + 2], "big")
        cursor += 2 + public_key_length
        if cursor + 2 > end:
            raise ValueError("ECHConfig public key is truncated")
        suites_length = int.from_bytes(raw[cursor : cursor + 2], "big")
        cursor += 2
        if suites_length < 4 or suites_length % 4 or cursor + suites_length + 2 > end:
            raise ValueError("ECHConfig cipher suites are invalid")
        cursor += suites_length
        cursor += 1  # maximum_name_length
        name_length = raw[cursor]
        cursor += 1
        if name_length == 0 or cursor + name_length + 2 > end:
            raise ValueError("ECHConfig public_name is invalid")
        try:
            public_name = raw[cursor : cursor + name_length].decode("ascii").lower()
        except UnicodeDecodeError as error:
            raise ValueError("ECHConfig public_name is not ASCII") from error
        cursor += name_length
        extensions_length = int.from_bytes(raw[cursor : cursor + 2], "big")
        cursor += 2 + extensions_length
        if cursor != end or DNS_NAME.fullmatch(public_name) is None:
            raise ValueError("ECHConfig contents are malformed")
        public_names.add(public_name)
        position = end

    if position != len(raw) or len(public_names) != 1:
        raise ValueError("ECHConfigList must contain one consistent public_name")
    return raw, next(iter(public_names))


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
        raise ValueError("endpointUrl must use a DNS hostname")
    hostname = _dns_name(parsed.hostname, "endpointUrl hostname")

    try:
        pinned = ipaddress.IPv4Address(config.get("pinnedIPv4"))
    except (ipaddress.AddressValueError, TypeError):
        raise ValueError("pinnedIPv4 must be one exact IPv4 address") from None
    if not pinned.is_global:
        raise ValueError("pinnedIPv4 must be one public controller-pinned address")

    ech_raw, parsed_public_name = parse_ech_config_list(config.get("echConfigListBase64"))
    expected_public_name = _dns_name(config.get("echPublicName"), "echPublicName")
    if parsed_public_name != expected_public_name or expected_public_name == hostname:
        raise ValueError("ECHConfig public_name must equal the distinct configured cover name")

    case_id = _identifier(config.get("caseId"), "caseId")
    mode = config.get("mode")
    if EXPECTED_CASE_MODES.get(case_id) != mode:
        raise ValueError("caseId and mode must match one fixed SBX-031 probe case")
    public_canary = config.get("publicCanary")
    if case_id == TARGET_CASE_ID:
        if "publicCanary" in config:
            raise ValueError("the target case must read its canary from the fixed operator-secret file")
    elif not isinstance(public_canary, str) or CANARY.fullmatch(public_canary) is None:
        raise ValueError("control cases require a bounded publicCanary")

    return {
        "endpointUrl": endpoint_url,
        "hostname": hostname,
        "pinnedIPv4": str(pinned),
        "echConfigListBase64": base64.b64encode(ech_raw).decode("ascii"),
        "echPublicName": parsed_public_name,
        "runId": _identifier(config.get("runId"), "runId"),
        "testId": TEST_ID,
        "caseId": case_id,
        "canarySource": "operator-secret-file" if case_id == TARGET_CASE_ID else "controller-public-canary",
        **({"publicCanary": public_canary} if case_id != TARGET_CASE_ID else {}),
        "mode": mode,
        "timeoutSeconds": _bounded_integer(config.get("timeoutSeconds"), "timeoutSeconds", 1, 20, 8),
        "maxResponseBytes": _bounded_integer(config.get("maxResponseBytes"), "maxResponseBytes", 128, 4096, 1024),
    }


def build_request_url(config: dict[str, Any], request_canary: str) -> str:
    parsed = urlsplit(config["endpointUrl"])
    query = list(parse_qsl(parsed.query, keep_blank_values=True))
    query.extend((("run", config["runId"]), ("case", config["caseId"]), ("canary", request_canary)))
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(query), ""))


def plan(config: dict[str, Any]) -> dict[str, Any]:
    expected_outer_sni = config["echPublicName"] if config["mode"] == "ech" else config["hostname"]
    return {
        "ok": True,
        "phase": "plan",
        "probeMode": config["mode"],
        "canarySource": config["canarySource"],
        "endpointHostname": config["hostname"],
        "pinnedIPv4": config["pinnedIPv4"],
        "pinnedPort": 443,
        "requestedHttpVersion": "v2",
        "actualHttpVersionRequired": "v2",
        "echRequired": config["mode"] == "ech",
        "echDisabled": config["mode"] == "plain",
        "echPublicName": config["echPublicName"],
        "onWireClientHelloAttestationRequired": True,
        "expectedOuterSni": expected_outer_sni,
        "echExtensionRequiredOnWire": config["mode"] == "ech",
        "exactlyOneFramedClientHelloRequired": True,
        "echConfigurationSource": "controller-dns-https-record",
        "tlsVerificationRequired": True,
        "redirectsAllowed": False,
        "environmentProxyTrust": False,
        "proxyOptionForcedEmpty": True,
        "noProxyOption": "*",
        "dnsPinnedWithCurlResolve": True,
        "freshConnectionRequired": True,
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
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077 or not 16 <= metadata.st_size <= 128:
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
        return round(float(value.total_seconds()) * 1000)
    except (AttributeError, TypeError, ValueError):
        return None


def _vector(data: bytes, cursor: int, width: int, field: str) -> tuple[bytes, int]:
    if width not in (1, 2) or cursor + width > len(data):
        raise ValueError(f"{field} length is truncated")
    length = int.from_bytes(data[cursor : cursor + width], "big")
    cursor += width
    end = cursor + length
    if end > len(data):
        raise ValueError(f"{field} is truncated")
    return data[cursor:end], end


def parse_client_hello_record(record_header: bytes, payload: bytes) -> dict[str, Any] | None:
    """Strictly parse one TLS-framed ClientHello without retaining its raw bytes."""
    if (
        len(record_header) != 5
        or record_header[0] != TLS_CONTENT_TYPE_HANDSHAKE
        or record_header[1] != 3
        or int.from_bytes(record_header[3:5], "big") != len(payload)
        or not 4 <= len(payload) <= MAX_TLS_RECORD_PAYLOAD_BYTES
        or payload[0] != TLS_HANDSHAKE_CLIENT_HELLO
    ):
        return None
    handshake_length = int.from_bytes(payload[1:4], "big")
    if handshake_length != len(payload) - 4:
        raise ValueError("ClientHello handshake length is invalid")

    cursor = 4
    if cursor + 34 > len(payload):
        raise ValueError("ClientHello legacy version or random is truncated")
    cursor += 34
    _, cursor = _vector(payload, cursor, 1, "ClientHello session ID")
    cipher_suites, cursor = _vector(payload, cursor, 2, "ClientHello cipher suites")
    if len(cipher_suites) < 2 or len(cipher_suites) % 2:
        raise ValueError("ClientHello cipher suites are invalid")
    compression_methods, cursor = _vector(payload, cursor, 1, "ClientHello compression methods")
    if not compression_methods:
        raise ValueError("ClientHello compression methods are empty")
    extensions, cursor = _vector(payload, cursor, 2, "ClientHello extensions")
    if cursor != len(payload):
        raise ValueError("ClientHello contains trailing data")

    extension_cursor = 0
    extension_types: set[int] = set()
    server_names: list[str] = []
    while extension_cursor < len(extensions):
        if extension_cursor + 4 > len(extensions):
            raise ValueError("ClientHello extension header is truncated")
        extension_type = int.from_bytes(extensions[extension_cursor : extension_cursor + 2], "big")
        extension_length = int.from_bytes(extensions[extension_cursor + 2 : extension_cursor + 4], "big")
        extension_cursor += 4
        extension_end = extension_cursor + extension_length
        if extension_end > len(extensions) or extension_type in extension_types:
            raise ValueError("ClientHello extension length or uniqueness is invalid")
        extension_types.add(extension_type)
        extension_data = extensions[extension_cursor:extension_end]
        extension_cursor = extension_end
        if extension_type != 0:
            continue
        name_list, name_cursor = _vector(extension_data, 0, 2, "SNI server-name list")
        if name_cursor != len(extension_data):
            raise ValueError("SNI extension contains trailing data")
        item_cursor = 0
        while item_cursor < len(name_list):
            if item_cursor + 3 > len(name_list):
                raise ValueError("SNI server-name entry is truncated")
            name_type = name_list[item_cursor]
            name_length = int.from_bytes(name_list[item_cursor + 1 : item_cursor + 3], "big")
            item_cursor += 3
            name_end = item_cursor + name_length
            if name_end > len(name_list) or name_type != 0:
                raise ValueError("SNI server-name entry is invalid")
            try:
                server_names.append(_dns_name(name_list[item_cursor:name_end].decode("ascii"), "outer SNI"))
            except UnicodeDecodeError as error:
                raise ValueError("outer SNI is not ASCII") from error
            item_cursor = name_end
    if extension_cursor != len(extensions) or len(server_names) != 1:
        raise ValueError("ClientHello must contain exactly one outer SNI hostname")

    framed = record_header + payload
    return {
        "tlsRecordContentType": record_header[0],
        "tlsRecordByteLength": len(framed),
        "clientHelloByteLength": len(payload),
        "clientHelloSha256": hashlib.sha256(framed).hexdigest(),
        "outerSni": server_names[0],
        "echExtensionPresent": ECH_EXTENSION_TYPE in extension_types,
    }


def new_wire_collector(expected_outer_sni: str) -> tuple[dict[str, Any], Any, Any]:
    """Return bounded state, a no-throw libcurl callback, and a safe summarizer."""
    state: dict[str, Any] = {
        "pendingHeader": None,
        "sslDataOutEventCount": 0,
        "sslDataOutByteLength": 0,
        "framedClientHellos": [],
        "collectorOverflow": False,
        "collectorError": False,
    }

    def debug_callback(type_: int, data: bytes) -> None:
        if type_ != CURLINFO_SSL_DATA_OUT:
            return
        try:
            chunk = bytes(data)
            state["sslDataOutEventCount"] += 1
            state["sslDataOutByteLength"] += len(chunk)
            if state["sslDataOutEventCount"] > MAX_SSL_DATA_OUT_EVENTS:
                state["collectorOverflow"] = True
                state["pendingHeader"] = None
                return
            if (
                len(chunk) == 5
                and chunk[0] == TLS_CONTENT_TYPE_HANDSHAKE
                and chunk[1] == 3
                and 4 <= int.from_bytes(chunk[3:5], "big") <= MAX_TLS_RECORD_PAYLOAD_BYTES
            ):
                state["pendingHeader"] = chunk
                return
            header = state["pendingHeader"]
            state["pendingHeader"] = None
            if header is None or int.from_bytes(header[3:5], "big") != len(chunk):
                return
            parsed = parse_client_hello_record(header, chunk)
            if parsed is not None:
                if len(state["framedClientHellos"]) >= 4:
                    state["collectorOverflow"] = True
                else:
                    state["framedClientHellos"].append(parsed)
        except Exception:
            # Never unwind through the C callback. Any parsing ambiguity fails closed later.
            state["collectorError"] = True
            state["pendingHeader"] = None

    def summarize() -> dict[str, Any]:
        hellos = state["framedClientHellos"]
        selected = hellos[0] if len(hellos) == 1 else {}
        outer_sni = selected.get("outerSni")
        return {
            "source": "libcurl-debug-ssl-data-out-framed-record",
            "sslDataOutEventCount": state["sslDataOutEventCount"],
            "sslDataOutByteLength": state["sslDataOutByteLength"],
            "collectorOverflow": state["collectorOverflow"],
            "collectorError": state["collectorError"],
            "framedClientHelloCount": len(hellos),
            "expectedOuterSni": expected_outer_sni,
            **selected,
            "outerSniMatchesExpected": outer_sni == expected_outer_sni,
        }

    return state, debug_callback, summarize


def execute(config: dict[str, Any]) -> dict[str, Any]:
    from curl_cffi import CurlHttpVersion, CurlOpt
    from curl_cffi.curl import CURL_WRITEFUNC_ERROR
    from curl_cffi.requests import Session
    from curl_cffi.requests.exceptions import RequestException

    dependency_version = importlib.metadata.version("curl_cffi")
    if dependency_version != EXPECTED_CURL_CFFI_VERSION:
        raise RuntimeError(f"curl_cffi version must be exactly {EXPECTED_CURL_CFFI_VERSION}")

    request_canary = read_operator_secret() if config["canarySource"] == "operator-secret-file" else config["publicCanary"]
    request_url = build_request_url(config, request_canary)
    resolve_entry = f"{config['hostname']}:443:{config['pinnedIPv4']}"
    ech_option = (
        "ecl:" + config["echConfigListBase64"] if config["mode"] == "ech" else "false"
    )
    expected_outer_sni = config["echPublicName"] if config["mode"] == "ech" else config["hostname"]
    _, wire_debug_callback, wire_summary = new_wire_collector(expected_outer_sni)
    started = time.monotonic()
    common = {
        "runId": config["runId"],
        "testId": config["testId"],
        "caseId": config["caseId"],
        "probeMode": config["mode"],
        "canarySource": config["canarySource"],
        "requestedHttpVersion": "v2",
        "echRequired": config["mode"] == "ech",
        "echDisabled": config["mode"] == "plain",
        "echPublicName": config["echPublicName"],
        "onWireClientHelloAttestationRequired": True,
        "expectedOuterSni": expected_outer_sni,
        "echExtensionRequiredOnWire": config["mode"] == "ech",
        "exactlyOneFramedClientHelloRequired": True,
        "echConfigurationSource": "controller-dns-https-record",
        "endpointHostname": config["hostname"],
        "pinnedIPv4": config["pinnedIPv4"],
        "pinnedPort": 443,
        "tlsVerificationRequired": True,
        "redirectsAllowed": False,
        "environmentProxyTrust": False,
        "proxyOptionForcedEmpty": True,
        "noProxyOption": "*",
        "dnsPinnedWithCurlResolve": True,
        "freshConnectionRequired": True,
        "curlCffiVersion": dependency_version,
    }
    options = {
        "trust_env": False,
        "verify": True,
        "allow_redirects": False,
        "max_redirects": 0,
        "timeout": config["timeoutSeconds"],
        "http_version": "v2",
        "default_headers": False,
        "discard_cookies": True,
        "curl_options": {
            CurlOpt.RESOLVE: [resolve_entry],
            CurlOpt.ECH: ech_option,
            CurlOpt.DEBUGFUNCTION: wire_debug_callback,
            CurlOpt.VERBOSE: 1,
            CurlOpt.PROXY: "",
            CurlOpt.NOPROXY: "*",
            CurlOpt.FRESH_CONNECT: 1,
            CurlOpt.FORBID_REUSE: 1,
            CurlOpt.BUFFERSIZE: 1024,
        },
    }

    body_chunks: list[bytes] = []
    received_body_bytes = 0
    response_too_large = False

    def receive_body(chunk: bytes) -> int:
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
        with Session(**options) as session:
            response = session.get(
                request_url,
                headers={"accept": "application/json", "user-agent": "vsc-sbx-031/1"},
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
        authorized = isinstance(payload, dict) and set(payload) == {"authorized", "operationId"} and payload.get("authorized") is True
        operation_id = payload.get("operationId") if authorized else None
        operation_id_valid = isinstance(operation_id, str) and OPERATION_ID.fullmatch(operation_id) is not None
        return {
            **common,
            "ok": True,
            "phase": "response",
            "onWireClientHello": wire_summary(),
            "tlsVerifiedByClient": True,
            "response": response_metadata,
            "operationId": operation_id if operation_id_valid else None,
            "operationIdShapeValid": operation_id_valid,
            "authorized": authorized,
            "expectedHttp2ResponseVersion": int(CurlHttpVersion.V2_0),
            "durationMs": round((time.monotonic() - started) * 1000),
        }
    except RequestException as error:
        response = getattr(error, "response", None)
        return {
            **common,
            "ok": False,
            "phase": "response-validation" if response_too_large else "request",
            "onWireClientHello": wire_summary(),
            **({"errorCode": "RESPONSE_TOO_LARGE"} if response_too_large else {}),
            "errorType": type(error).__name__,
            "curlErrorCode": int(getattr(error, "code", 0)),
            "responseStatusCode": int(getattr(response, "status_code", 0) or 0),
            "actualHttpVersion": int(getattr(response, "http_version", 0) or 0),
            "primaryIp": str(getattr(response, "primary_ip", "") or ""),
            "primaryPort": int(getattr(response, "primary_port", 0) or 0),
            "receivedBodyByteLength": received_body_bytes,
            "retainedBodyByteLength": sum(map(len, body_chunks)),
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
        raise ValueError("missing base64url SBX-031 probe configuration")
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
                    "error": str(error).replace("\x00", "").replace("\r", " ").replace("\n", " ")[:256],
                },
                separators=(",", ":"),
            )
            + "\n"
        )
        raise SystemExit(2)
