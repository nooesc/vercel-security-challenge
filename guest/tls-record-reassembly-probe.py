#!/usr/bin/env python3
"""Bounded TLS ClientHello record-reassembly probe for SBX-032."""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import re
import socket
import ssl
import stat
import sys
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode, urlsplit


SCOPE_CONFIRMATION = "I_CONTROL_BOTH_ENDPOINTS_AND_AUTHORIZE_BOUNDED_TLS_REASSEMBLY_TESTING"
TEST_ID = "SBX-032-POC"
OPERATOR_SECRET_PATH = "/tmp/sbx-032/operator-secret"
TLS_HANDSHAKE_CONTENT_TYPE = 22
CLIENT_HELLO_HANDSHAKE_TYPE = 1
MAX_TLS_PLAINTEXT_FRAGMENT = 16_384
MAX_INITIAL_FLIGHT_BYTES = 65_536
TARGET_CASE_ID = "restricted-record-fragmented-b-target"
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
CANARY = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
DNS_NAME = re.compile(
    r"^(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
OPERATION_ID = re.compile(r"^h3_[A-Za-z0-9_-]{43}$")
ALLOWED_CONFIGURATION_KEYS = frozenset(
    (
        "scopeConfirmation",
        "allowedEndpointUrl",
        "allowedPinnedIPv4",
        "deniedEndpointUrl",
        "deniedPinnedIPv4",
        "runId",
        "testId",
        "caseId",
        "transmissionMode",
        "publicCanary",
        "timeoutSeconds",
        "maxResponseBytes",
    )
)
CASE_PLAN: dict[str, tuple[str, str, str]] = {
    "allow-normal-b-control": ("denied", "normal", "controller-public-canary"),
    "allow-tcp-segmented-b-control": ("denied", "tcp-segmented", "controller-public-canary"),
    "allow-record-fragmented-b-control": ("denied", "record-fragmented", "controller-public-canary"),
    "restricted-normal-a-control": ("allowed", "normal", "controller-public-canary"),
    "restricted-record-fragmented-a-control": ("allowed", "record-fragmented", "controller-public-canary"),
    "restricted-normal-b-negative": ("denied", "normal", "controller-public-canary"),
    TARGET_CASE_ID: ("denied", "record-fragmented", "operator-secret-file"),
    "restricted-record-fragmented-b-public-negative": ("denied", "record-fragmented", "controller-public-canary"),
    "restricted-normal-b-post-negative": ("denied", "normal", "controller-public-canary"),
}


class ConfigurationError(ValueError):
    pass


class IncompleteHttpResponse(ValueError):
    pass


@dataclass(frozen=True)
class TlsRecord:
    offset: int
    content_type: int
    version: bytes
    payload: bytes


def _record(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConfigurationError(f"{field} must be an object")
    return value


def _identifier(value: Any, field: str) -> str:
    if not isinstance(value, str) or IDENTIFIER.fullmatch(value) is None:
        raise ConfigurationError(f"{field} must be a bounded identifier")
    return value


def _bounded_integer(value: Any, field: str, minimum: int, maximum: int, fallback: int) -> int:
    selected = fallback if value is None else value
    if isinstance(selected, bool) or not isinstance(selected, int) or not minimum <= selected <= maximum:
        raise ConfigurationError(f"{field} must be an integer from {minimum} through {maximum}")
    return selected


def _dns_name(value: Any, field: str) -> str:
    if not isinstance(value, str) or value != value.strip():
        raise ConfigurationError(f"{field} must be a canonical DNS hostname")
    try:
        canonical = value.encode("idna").decode("ascii").lower()
    except UnicodeError as error:
        raise ConfigurationError(f"{field} must be a canonical DNS hostname") from error
    if canonical != value or DNS_NAME.fullmatch(canonical) is None:
        raise ConfigurationError(f"{field} must be a lowercase canonical DNS hostname")
    return canonical


def _endpoint(value: Any, field: str) -> dict[str, str]:
    if not isinstance(value, str) or value != value.strip():
        raise ConfigurationError(f"{field} must be a canonical HTTPS URL")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port not in (None, 443)
        or parsed.path != "/v1/h3-action"
        or parsed.query
        or parsed.fragment
    ):
        raise ConfigurationError(
            f"{field} must be HTTPS on port 443 at /v1/h3-action without credentials, query, or fragment"
        )
    try:
        ipaddress.ip_address(parsed.hostname)
    except ValueError:
        pass
    else:
        raise ConfigurationError(f"{field} must use a DNS hostname")
    hostname = _dns_name(parsed.hostname, f"{field} hostname")
    expected = f"https://{hostname}/v1/h3-action"
    if value != expected:
        raise ConfigurationError(f"{field} must use exact canonical form {expected}")
    return {"url": expected, "hostname": hostname, "path": parsed.path}


def _public_ipv4(value: Any, field: str) -> str:
    try:
        address = ipaddress.IPv4Address(value)
    except (ipaddress.AddressValueError, TypeError):
        raise ConfigurationError(f"{field} must be one exact IPv4 address") from None
    if not address.is_global:
        raise ConfigurationError(f"{field} must be a public controller-pinned IPv4 address")
    return str(address)


def validate_configuration(value: Any) -> dict[str, Any]:
    config = _record(value, "configuration")
    unknown = sorted(set(config) - ALLOWED_CONFIGURATION_KEYS)
    if unknown:
        raise ConfigurationError(f"configuration field {json.dumps(unknown[0])} is not allowed")
    if config.get("scopeConfirmation") != SCOPE_CONFIRMATION:
        raise ConfigurationError(f"scopeConfirmation must equal {json.dumps(SCOPE_CONFIRMATION)}")
    if config.get("testId") != TEST_ID:
        raise ConfigurationError(f"testId must equal {json.dumps(TEST_ID)}")

    allowed = _endpoint(config.get("allowedEndpointUrl"), "allowedEndpointUrl")
    denied = _endpoint(config.get("deniedEndpointUrl"), "deniedEndpointUrl")
    if allowed["hostname"] == denied["hostname"]:
        raise ConfigurationError("allowed and denied endpoint hostnames must be distinct")
    allowed_ip = _public_ipv4(config.get("allowedPinnedIPv4"), "allowedPinnedIPv4")
    denied_ip = _public_ipv4(config.get("deniedPinnedIPv4"), "deniedPinnedIPv4")

    run_id = _identifier(config.get("runId"), "runId")
    case_id = _identifier(config.get("caseId"), "caseId")
    case_plan = CASE_PLAN.get(case_id)
    if case_plan is None:
        raise ConfigurationError("caseId is not one fixed SBX-032 case")
    endpoint_role, expected_mode, canary_source = case_plan
    if config.get("transmissionMode") != expected_mode:
        raise ConfigurationError("caseId and transmissionMode do not match the fixed proof matrix")

    if canary_source == "operator-secret-file":
        if "publicCanary" in config:
            raise ConfigurationError("the target case must read only the fixed operator-secret file")
    else:
        public_canary = config.get("publicCanary")
        if not isinstance(public_canary, str) or CANARY.fullmatch(public_canary) is None:
            raise ConfigurationError("control cases require one bounded publicCanary")

    endpoint = allowed if endpoint_role == "allowed" else denied
    pinned_ip = allowed_ip if endpoint_role == "allowed" else denied_ip
    return {
        "allowedEndpoint": allowed,
        "allowedPinnedIPv4": allowed_ip,
        "deniedEndpoint": denied,
        "deniedPinnedIPv4": denied_ip,
        "endpoint": endpoint,
        "endpointRole": endpoint_role,
        "pinnedIPv4": pinned_ip,
        "runId": run_id,
        "testId": TEST_ID,
        "caseId": case_id,
        "transmissionMode": expected_mode,
        "canarySource": canary_source,
        **({"publicCanary": config["publicCanary"]} if canary_source != "operator-secret-file" else {}),
        "timeoutSeconds": _bounded_integer(config.get("timeoutSeconds"), "timeoutSeconds", 1, 15, 8),
        "maxResponseBytes": _bounded_integer(config.get("maxResponseBytes"), "maxResponseBytes", 128, 4096, 1024),
    }


def plan(config: dict[str, Any]) -> dict[str, Any]:
    return {
        "ok": True,
        "phase": "plan",
        "runId": config["runId"],
        "testId": TEST_ID,
        "caseId": config["caseId"],
        "endpointRole": config["endpointRole"],
        "transmissionMode": config["transmissionMode"],
        "canarySource": config["canarySource"],
        "endpointHostname": config["endpoint"]["hostname"],
        "pinnedIPv4": config["pinnedIPv4"],
        "pinnedPort": 443,
        "maximumRequests": 1,
        "retryCount": 0,
        "redirectsAllowed": False,
        "freshConnectionRequired": True,
        "environmentProxyTrust": False,
        "strictCertificateVerification": True,
        "hostnameVerificationRequired": True,
        "requiredAlpn": "http/1.1",
        "initialClientHelloSource": "python-sslobject-memorybio",
        "recordSplitRequired": config["transmissionMode"] == "record-fragmented",
        "tcpWriteSplitRequired": config["transmissionMode"] == "tcp-segmented",
        "splitLocationRequired": "server_name.hostname",
        "operatorSecretPathFixed": config["canarySource"] == "operator-secret-file",
        "maximumResponseBytes": config["maxResponseBytes"],
        "timeoutSeconds": config["timeoutSeconds"],
    }


def parse_tls_records(data: bytes) -> list[TlsRecord]:
    if not data or len(data) > MAX_INITIAL_FLIGHT_BYTES:
        raise ValueError("initial TLS flight is empty or oversized")
    records: list[TlsRecord] = []
    offset = 0
    while offset < len(data):
        if offset + 5 > len(data):
            raise ValueError("TLS record header is truncated")
        payload_length = int.from_bytes(data[offset + 3 : offset + 5], "big")
        if payload_length <= 0 or payload_length > MAX_TLS_PLAINTEXT_FRAGMENT:
            raise ValueError("TLS record payload length is invalid")
        end = offset + 5 + payload_length
        if end > len(data):
            raise ValueError("TLS record payload is truncated")
        records.append(TlsRecord(offset, data[offset], data[offset + 1 : offset + 3], data[offset + 5 : end]))
        offset = end
    return records


def locate_client_hello_sni_split(payload: bytes, expected_hostname: str) -> tuple[int, int, int, int]:
    if len(payload) < 4 or payload[0] != CLIENT_HELLO_HANDSHAKE_TYPE:
        raise ValueError("first plaintext handshake record is not ClientHello")
    handshake_length = int.from_bytes(payload[1:4], "big")
    if handshake_length + 4 != len(payload):
        raise ValueError("ClientHello must occupy exactly one original TLS record")
    body = payload[4:]
    cursor = 2 + 32
    if cursor + 1 > len(body):
        raise ValueError("ClientHello legacy fields are truncated")
    session_id_length = body[cursor]
    cursor += 1 + session_id_length
    if cursor + 2 > len(body):
        raise ValueError("ClientHello cipher suites are truncated")
    cipher_suites_length = int.from_bytes(body[cursor : cursor + 2], "big")
    cursor += 2 + cipher_suites_length
    if cipher_suites_length < 2 or cipher_suites_length % 2 or cursor + 1 > len(body):
        raise ValueError("ClientHello cipher suites are invalid")
    compression_methods_length = body[cursor]
    cursor += 1 + compression_methods_length
    if cursor + 2 > len(body):
        raise ValueError("ClientHello extensions length is missing")
    extensions_length = int.from_bytes(body[cursor : cursor + 2], "big")
    cursor += 2
    extensions_end = cursor + extensions_length
    if extensions_end != len(body):
        raise ValueError("ClientHello extensions are truncated or trailing")

    while cursor < extensions_end:
        if cursor + 4 > extensions_end:
            raise ValueError("ClientHello extension header is truncated")
        extension_type = int.from_bytes(body[cursor : cursor + 2], "big")
        extension_length = int.from_bytes(body[cursor + 2 : cursor + 4], "big")
        extension_data_start = cursor + 4
        extension_end = extension_data_start + extension_length
        if extension_end > extensions_end:
            raise ValueError("ClientHello extension data is truncated")
        if extension_type == 0:
            extension = body[extension_data_start:extension_end]
            if len(extension) < 5 or int.from_bytes(extension[0:2], "big") != len(extension) - 2:
                raise ValueError("SNI extension list is malformed")
            name_type = extension[2]
            name_length = int.from_bytes(extension[3:5], "big")
            if name_type != 0 or name_length < 2 or 5 + name_length != len(extension):
                raise ValueError("SNI extension must contain exactly one DNS hostname")
            try:
                hostname = extension[5:].decode("ascii").lower()
            except UnicodeDecodeError as error:
                raise ValueError("SNI hostname is not ASCII") from error
            if hostname != expected_hostname:
                raise ValueError("ClientHello SNI did not match the configured endpoint hostname")
            hostname_start_in_body = extension_data_start + 5
            split_in_body = hostname_start_in_body + max(1, name_length // 2)
            split_in_payload = 4 + split_in_body
            hostname_start_in_payload = 4 + hostname_start_in_body
            hostname_end_in_payload = hostname_start_in_payload + name_length
            if not hostname_start_in_payload < split_in_payload < hostname_end_in_payload <= len(payload):
                raise ValueError("SNI split point is not internal to the ClientHello record")
            return split_in_payload, name_length, hostname_start_in_payload, hostname_end_in_payload
        cursor = extension_end
    raise ValueError("ClientHello did not contain an SNI extension")


def _record_header(content_type: int, version: bytes, payload_length: int) -> bytes:
    if len(version) != 2 or not 0 < payload_length <= MAX_TLS_PLAINTEXT_FRAGMENT:
        raise ValueError("cannot construct TLS record header")
    return bytes((content_type,)) + version + payload_length.to_bytes(2, "big")


def build_tls_session(hostname: str) -> tuple[ssl.SSLObject, ssl.MemoryBIO, ssl.MemoryBIO, bytes]:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_default_certs(ssl.Purpose.SERVER_AUTH)
    context.set_alpn_protocols(["http/1.1"])
    if context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname:
        raise RuntimeError("strict TLS verification context was not established")
    incoming = ssl.MemoryBIO()
    outgoing = ssl.MemoryBIO()
    tls = context.wrap_bio(incoming, outgoing, server_side=False, server_hostname=hostname)
    try:
        tls.do_handshake()
    except ssl.SSLWantReadError:
        pass
    initial = outgoing.read()
    if not initial:
        raise RuntimeError("SSLObject did not emit an initial ClientHello flight")
    return tls, incoming, outgoing, initial


def prepare_initial_flight(hostname: str, mode: str) -> tuple[ssl.SSLObject, ssl.MemoryBIO, ssl.MemoryBIO, bytes, int, dict[str, Any]]:
    tls, incoming, outgoing, original = build_tls_session(hostname)
    records = parse_tls_records(original)
    if records[0].offset != 0 or records[0].content_type != TLS_HANDSHAKE_CONTENT_TYPE:
        raise ValueError("ClientHello was not the first plaintext TLS handshake record")
    first = records[0]
    split_in_payload, sni_length, sni_start, sni_end = locate_client_hello_sni_split(first.payload, hostname)
    first_fragment = first.payload[:split_in_payload]
    second_fragment = first.payload[split_in_payload:]
    split_absolute = first.offset + 5 + split_in_payload
    fragmented = b"".join(
        (
            original[: first.offset],
            _record_header(first.content_type, first.version, len(first_fragment)),
            first_fragment,
            _record_header(first.content_type, first.version, len(second_fragment)),
            second_fragment,
            original[first.offset + 5 + len(first.payload) :],
        )
    )
    transmitted = fragmented if mode == "record-fragmented" else original
    transmitted_records = parse_tls_records(transmitted)
    if mode == "record-fragmented":
        transmitted_first, transmitted_second = transmitted_records[:2]
        if (
            transmitted_first.content_type != first.content_type
            or transmitted_second.content_type != first.content_type
            or transmitted_first.version != first.version
            or transmitted_second.version != first.version
        ):
            raise RuntimeError("fragmented records changed the original record type or version")
        reassembled = transmitted_first.payload + transmitted_second.payload
        original_tail = [(item.content_type, item.version, item.payload) for item in records[1:]]
        transmitted_tail = [(item.content_type, item.version, item.payload) for item in transmitted_records[2:]]
        if transmitted_tail != original_tail:
            raise RuntimeError("record fragmentation changed records after the ClientHello")
    else:
        reassembled = transmitted_records[0].payload
    payload_sha = hashlib.sha256(first.payload).hexdigest()
    reassembled_sha = hashlib.sha256(reassembled).hexdigest()
    if reassembled != first.payload or reassembled_sha != payload_sha:
        raise RuntimeError("record fragmentation did not preserve the ClientHello payload")
    expected_record_count = len(records) + (1 if mode == "record-fragmented" else 0)
    if len(transmitted_records) != expected_record_count:
        raise RuntimeError("transmitted TLS record count was not deterministic")

    metadata: dict[str, Any] = {
        "source": "python-sslobject-memorybio",
        "outerSni": hostname,
        "sniHostnameByteLength": sni_length,
        "sniHostnameStartOffsetInRecordPayload": sni_start,
        "sniHostnameEndOffsetInRecordPayload": sni_end,
        "originalRecordCount": len(records),
        "transmittedRecordCount": len(transmitted_records),
        "originalFirstFlightByteLength": len(original),
        "transmittedFirstFlightByteLength": len(transmitted),
        "originalFirstFlightSha256": hashlib.sha256(original).hexdigest(),
        "transmittedFirstFlightSha256": hashlib.sha256(transmitted).hexdigest(),
        "clientHelloPayloadSha256": payload_sha,
        "reassembledClientHelloPayloadSha256": reassembled_sha,
        "reassemblyMatchesOriginal": True,
        "splitLocation": "server_name.hostname",
        "splitOffsetInRecordPayload": split_in_payload,
        "originalRecordPayloadLength": len(first.payload),
        "fragmentPayloadLengths": [len(first_fragment), len(second_fragment)],
        "recordContentType": first.content_type,
        "recordLegacyVersionHex": first.version.hex(),
        "initialSocketWriteCount": 0,
        "rawClientHelloRetained": False,
    }
    return tls, incoming, outgoing, transmitted, split_absolute, metadata


def _drain_outgoing(outgoing: ssl.MemoryBIO, sock: socket.socket) -> int:
    writes = 0
    while outgoing.pending:
        chunk = outgoing.read()
        if not chunk:
            break
        sock.sendall(chunk)
        writes += 1
    return writes


def _send_initial(
    sock: socket.socket,
    original_or_fragmented: bytes,
    original_split_absolute: int,
    mode: str,
) -> int:
    if mode == "tcp-segmented":
        if not 0 < original_split_absolute < len(original_or_fragmented):
            raise RuntimeError("TCP write split point was invalid")
        sock.sendall(original_or_fragmented[:original_split_absolute])
        time.sleep(0.04)
        sock.sendall(original_or_fragmented[original_split_absolute:])
        return 2
    sock.sendall(original_or_fragmented)
    return 1


def _complete_handshake(
    tls: ssl.SSLObject,
    incoming: ssl.MemoryBIO,
    outgoing: ssl.MemoryBIO,
    sock: socket.socket,
) -> None:
    for _ in range(256):
        try:
            tls.do_handshake()
            _drain_outgoing(outgoing, sock)
            return
        except ssl.SSLWantReadError:
            _drain_outgoing(outgoing, sock)
            encrypted = sock.recv(16_384)
            if not encrypted:
                raise ssl.SSLEOFError("peer closed during TLS handshake")
            incoming.write(encrypted)
        except ssl.SSLWantWriteError:
            _drain_outgoing(outgoing, sock)
    raise TimeoutError("TLS handshake iteration bound exceeded")


def _tls_write_all(tls: ssl.SSLObject, outgoing: ssl.MemoryBIO, sock: socket.socket, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        try:
            written = tls.write(data[offset:])
            if written <= 0:
                raise RuntimeError("SSLObject made no application-write progress")
            offset += written
            _drain_outgoing(outgoing, sock)
        except ssl.SSLWantWriteError:
            _drain_outgoing(outgoing, sock)
    _drain_outgoing(outgoing, sock)


def _read_http_response(
    tls: ssl.SSLObject,
    incoming: ssl.MemoryBIO,
    outgoing: ssl.MemoryBIO,
    sock: socket.socket,
    maximum_cleartext_bytes: int,
) -> bytes:
    response = bytearray()
    for _ in range(512):
        try:
            chunk = tls.read(4_096)
            if chunk:
                response.extend(chunk)
                if len(response) > maximum_cleartext_bytes:
                    raise ValueError("HTTP response exceeded the fixed cleartext bound")
                try:
                    parse_http_response(bytes(response), maximum_cleartext_bytes)
                    return bytes(response)
                except IncompleteHttpResponse:
                    continue
            else:
                break
        except ssl.SSLWantReadError:
            _drain_outgoing(outgoing, sock)
            encrypted = sock.recv(16_384)
            if not encrypted:
                break
            incoming.write(encrypted)
        except ssl.SSLZeroReturnError:
            break
    return bytes(response)


def _decode_chunked(data: bytes, maximum_body_bytes: int) -> tuple[bytes, int]:
    body = bytearray()
    cursor = 0
    while True:
        line_end = data.find(b"\r\n", cursor)
        if line_end < 0:
            raise IncompleteHttpResponse("chunk-size line is incomplete")
        size_token = data[cursor:line_end].split(b";", 1)[0]
        try:
            size = int(size_token, 16)
        except ValueError as error:
            raise ValueError("chunk-size line is invalid") from error
        cursor = line_end + 2
        if size == 0:
            if len(data) < cursor + 2:
                raise IncompleteHttpResponse("final chunk is incomplete")
            if data[cursor : cursor + 2] == b"\r\n":
                return bytes(body), cursor + 2
            trailer_end = data.find(b"\r\n\r\n", cursor)
            if trailer_end < 0:
                raise IncompleteHttpResponse("chunk trailers are incomplete")
            return bytes(body), trailer_end + 4
        if size < 0 or len(body) + size > maximum_body_bytes:
            raise ValueError("chunked body exceeded the fixed bound")
        end = cursor + size
        if len(data) < end + 2:
            raise IncompleteHttpResponse("chunk data is incomplete")
        if data[end : end + 2] != b"\r\n":
            raise ValueError("chunk data terminator is invalid")
        body.extend(data[cursor:end])
        cursor = end + 2


def parse_http_response(raw: bytes, maximum_body_bytes: int) -> dict[str, Any]:
    header_end = raw.find(b"\r\n\r\n")
    if header_end < 0:
        if len(raw) > 16_384:
            raise ValueError("HTTP response headers exceeded the fixed bound")
        raise IncompleteHttpResponse("HTTP response headers are incomplete")
    if header_end > 16_384:
        raise ValueError("HTTP response headers exceeded the fixed bound")
    try:
        header_text = raw[:header_end].decode("iso-8859-1")
    except UnicodeDecodeError as error:
        raise ValueError("HTTP response headers were not decodable") from error
    lines = header_text.split("\r\n")
    status_match = re.fullmatch(r"HTTP/1\.[01] ([0-9]{3})(?: .*)?", lines[0])
    if status_match is None:
        raise ValueError("HTTP response status line was invalid")
    status_code = int(status_match.group(1))
    headers: dict[str, list[str]] = {}
    for line in lines[1:]:
        if ":" not in line or line[0] in " \t":
            raise ValueError("HTTP response contained a malformed header")
        name, value = line.split(":", 1)
        name = name.lower()
        if re.fullmatch(r"[!#$%&'*+.^_`|~0-9a-z-]+", name) is None:
            raise ValueError("HTTP response header name was invalid")
        headers.setdefault(name, []).append(value.strip())
    data = raw[header_end + 4 :]
    transfer_encoding = ",".join(headers.get("transfer-encoding", [])).lower()
    content_lengths = headers.get("content-length", [])
    if transfer_encoding:
        if transfer_encoding != "chunked" or content_lengths:
            raise ValueError("HTTP response transfer framing was ambiguous")
        body, consumed = _decode_chunked(data, maximum_body_bytes)
    else:
        if len(content_lengths) != 1 or not content_lengths[0].isdigit():
            raise ValueError("HTTP response requires one explicit Content-Length or chunked encoding")
        content_length = int(content_lengths[0])
        if content_length > maximum_body_bytes:
            raise ValueError("HTTP response body exceeded the fixed bound")
        if len(data) < content_length:
            raise IncompleteHttpResponse("HTTP response body is incomplete")
        body = data[:content_length]
        consumed = content_length
    if len(data) != consumed:
        raise ValueError("HTTP response contained trailing bytes")
    return {
        "statusCode": status_code,
        "headers": headers,
        "body": body,
    }


def _load_operator_secret() -> str:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(OPERATOR_SECRET_PATH, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600:
            raise ValueError("operator-secret file must be a regular mode-0600 file")
        if metadata.st_size < 16 or metadata.st_size > 128:
            raise ValueError("operator-secret file size was outside the fixed bound")
        data = os.read(descriptor, 129)
        if len(data) != metadata.st_size:
            raise ValueError("operator-secret file read was incomplete")
    finally:
        os.close(descriptor)
    try:
        secret = data.decode("ascii")
    except UnicodeDecodeError as error:
        raise ValueError("operator-secret file was not ASCII") from error
    if CANARY.fullmatch(secret) is None:
        raise ValueError("operator-secret file did not contain one bounded canary")
    return secret


def _safe_error(error: BaseException, secret: str | None) -> str:
    message = str(error).replace("\x00", " ").replace("\r", " ").replace("\n", " ")
    if secret:
        message = message.replace(secret, "[REDACTED]")
    return message[:512]


def _emit(result: dict[str, Any], secret: str | None = None) -> None:
    serialized = json.dumps(result, separators=(",", ":"), sort_keys=True)
    if secret:
        serialized = serialized.replace(secret, "[REDACTED]")
    print(serialized)


def execute(config: dict[str, Any]) -> dict[str, Any]:
    result = plan(config)
    result["phase"] = "client-hello"
    secret: str | None = None
    sock: socket.socket | None = None
    phase = "client-hello"
    try:
        hostname = config["endpoint"]["hostname"]
        tls, incoming, outgoing, transmitted, split_absolute, hello = prepare_initial_flight(
            hostname, config["transmissionMode"]
        )
        result["clientHello"] = hello
        canary = _load_operator_secret() if config["canarySource"] == "operator-secret-file" else config["publicCanary"]
        secret = canary if config["canarySource"] == "operator-secret-file" else None

        phase = "connect"
        result["phase"] = phase
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.settimeout(config["timeoutSeconds"])
        started = time.monotonic()
        sock.connect((config["pinnedIPv4"], 443))
        peer = sock.getpeername()
        if peer[0] != config["pinnedIPv4"] or peer[1] != 443:
            raise RuntimeError("connected peer did not match the controller-pinned IPv4 and port")
        result["peerIPv4"] = peer[0]
        result["peerPort"] = peer[1]

        phase = "handshake"
        result["phase"] = phase
        hello["initialSocketWriteCount"] = _send_initial(
            sock, transmitted, split_absolute, config["transmissionMode"]
        )
        _complete_handshake(tls, incoming, outgoing, sock)
        certificate = tls.getpeercert()
        certificate_der = tls.getpeercert(binary_form=True)
        selected_alpn = tls.selected_alpn_protocol()
        if not certificate or not certificate_der:
            raise ssl.SSLError("verified peer certificate was unavailable")
        if selected_alpn != "http/1.1":
            raise ssl.SSLError("server did not select required http/1.1 ALPN")
        result.update(
            {
                "certificateVerified": True,
                "hostnameVerified": True,
                "selectedAlpn": selected_alpn,
                "tlsVersion": tls.version(),
                "cipherSuite": tls.cipher()[0] if tls.cipher() else None,
                "peerCertificateSha256": hashlib.sha256(certificate_der).hexdigest(),
            }
        )

        phase = "request"
        result["phase"] = phase
        query = urlencode({"run": config["runId"], "case": config["caseId"], "canary": canary})
        request_target = f"{config['endpoint']['path']}?{query}"
        request = (
            f"GET {request_target} HTTP/1.1\r\n"
            f"Host: {hostname}\r\n"
            "Accept: application/json\r\n"
            "Connection: close\r\n"
            "User-Agent: sbx-032-bounded-probe/1\r\n\r\n"
        ).encode("ascii")
        _tls_write_all(tls, outgoing, sock, request)
        raw_response = _read_http_response(
            tls, incoming, outgoing, sock, min(20_000, config["maxResponseBytes"] + 16_384)
        )
        parsed = parse_http_response(raw_response, config["maxResponseBytes"])
        body = parsed["body"]
        if canary.encode("ascii") in body:
            raise ValueError("owned endpoint reflected the request canary")
        content_types = parsed["headers"].get("content-type", [])
        cache_controls = parsed["headers"].get("cache-control", [])
        if parsed["statusCode"] != 200:
            raise ValueError(f"owned endpoint returned non-success status {parsed['statusCode']}")
        if len(content_types) != 1 or not content_types[0].lower().startswith("application/json"):
            raise ValueError("owned endpoint returned an unexpected content type")
        cache_directives = {
            item.strip().lower()
            for value in cache_controls
            for item in value.split(",")
        }
        if "no-store" not in cache_directives:
            raise ValueError("owned endpoint response did not require no-store")
        try:
            payload = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("owned endpoint response was not valid JSON") from error
        if not isinstance(payload, dict) or payload.get("authorized") is not True:
            raise ValueError("owned endpoint did not authorize the operation")
        operation_id = payload.get("operationId")
        if not isinstance(operation_id, str) or OPERATION_ID.fullmatch(operation_id) is None:
            raise ValueError("owned endpoint operation ID had an invalid shape")

        result.update(
            {
                "ok": True,
                "phase": "response",
                "operationId": operation_id,
                "operationIdShapeValid": True,
                "authorized": True,
                "response": {
                    "statusCode": parsed["statusCode"],
                    "contentType": content_types[0],
                    "cacheControl": ", ".join(cache_controls),
                    "bodyByteLength": len(body),
                    "bodySha256": hashlib.sha256(body).hexdigest(),
                    "bodyContainsCanary": False,
                    "rawBodyRetained": False,
                },
                "durationMs": round((time.monotonic() - started) * 1000),
            }
        )
        return result
    except BaseException as error:
        timed_out = isinstance(error, (socket.timeout, TimeoutError))
        active = isinstance(
            error,
            (
                BrokenPipeError,
                ConnectionAbortedError,
                ConnectionRefusedError,
                ConnectionResetError,
                ssl.SSLEOFError,
                ssl.SSLZeroReturnError,
            ),
        )
        result.update(
            {
                "ok": False,
                "phase": phase,
                "errorType": type(error).__name__,
                "errorErrno": getattr(error, "errno", None),
                "errorMessage": _safe_error(error, secret),
                "timeout": timed_out,
                "responseStatusCode": 0,
            }
        )
        result["_exitCode"] = 11 if timed_out else (10 if active else 12)
        return result
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def _decode_argument(value: str) -> Any:
    try:
        padded = value + "=" * ((4 - len(value) % 4) % 4)
        decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
        return json.loads(decoded)
    except (UnicodeEncodeError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
        raise ConfigurationError("configuration argument was not canonical base64url JSON") from error


def main(argv: list[str]) -> int:
    if len(argv) not in (2, 3) or (len(argv) == 3 and argv[2] not in ("--plan", "--inspect-first-flight")):
        _emit({"ok": False, "phase": "configuration", "errorType": "UsageError"})
        return 2
    try:
        config = validate_configuration(_decode_argument(argv[1]))
    except ConfigurationError as error:
        _emit({"ok": False, "phase": "configuration", "errorType": type(error).__name__, "errorMessage": str(error)[:512]})
        return 2
    if len(argv) == 3 and argv[2] == "--plan":
        _emit(plan(config))
        return 0
    if len(argv) == 3 and argv[2] == "--inspect-first-flight":
        try:
            _, _, _, _, _, hello = prepare_initial_flight(
                config["endpoint"]["hostname"], config["transmissionMode"]
            )
            hello["initialSocketWriteCount"] = 2 if config["transmissionMode"] == "tcp-segmented" else 1
            _emit({**plan(config), "phase": "client-hello", "clientHello": hello})
            return 0
        except BaseException as error:
            _emit({"ok": False, "phase": "client-hello", "errorType": type(error).__name__, "errorMessage": str(error)[:512]})
            return 12

    result = execute(config)
    exit_code = int(result.pop("_exitCode", 0))
    secret = None
    if config["canarySource"] == "operator-secret-file":
        try:
            secret = _load_operator_secret()
        except BaseException:
            secret = None
    _emit(result, secret)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
