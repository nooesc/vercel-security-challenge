#!/usr/bin/env python3
"""One-shot, strict-TLS fixed-address probe for SBX-033.

The probe emits only a bounded JSON attestation. It never emits a request
canary, response body, token, or reversible secret digest.
"""

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
import uuid
from typing import Any
from urllib.parse import urlsplit


TEST_ID = "SBX-033-POC"
SCOPE_CONFIRMATION = "I_CONTROL_THE_ENDPOINT_AND_AUTHORIZE_BOUNDED_NATIVE_IPV6_DENY_TESTING"
SECRET_PATH = "/tmp/sbx-033/operator-secret"
CASE_FAMILIES = {
    "allow-v4-control": ("ipv4", "controller-public-canary"),
    "allow-v6-control": ("ipv6", "controller-public-canary"),
    "deny-v4-control": ("ipv4", "controller-public-canary"),
    "deny-v6-public": ("ipv6", "controller-public-canary"),
    "deny-v6-secret-target": ("ipv6", "operator-secret-file"),
}
IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
CANARY_PATTERN = re.compile(rb"^[A-Za-z0-9_-]{24,128}$")
DNS_NAME_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
OPERATION_ID_PATTERN = re.compile(r"^h3_[A-Za-z0-9_-]{43}$")


class ConfigurationError(Exception):
    pass


def emit(value: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(value, separators=(",", ":"), sort_keys=True) + "\n")


def decode_configuration(encoded: str) -> dict[str, Any]:
    if not encoded or len(encoded) > 32_768 or not re.fullmatch(r"[A-Za-z0-9_-]+", encoded):
        raise ConfigurationError("configuration envelope is not bounded base64url")
    padding = "=" * ((4 - len(encoded) % 4) % 4)
    try:
        raw = base64.b64decode(encoded + padding, altchars=b"-_", validate=True)
        value = json.loads(raw)
    except Exception as error:
        raise ConfigurationError("configuration envelope is invalid") from error
    if not isinstance(value, dict):
        raise ConfigurationError("configuration must be an object")
    return value


def exact_keys(value: dict[str, Any], expected: set[str]) -> None:
    if set(value) != expected:
        raise ConfigurationError("configuration keys are not exact")


def canonical_uuid(value: Any) -> str:
    if not isinstance(value, str):
        raise ConfigurationError("runId must be a canonical UUID")
    try:
        parsed = uuid.UUID(value)
    except ValueError as error:
        raise ConfigurationError("runId must be a canonical UUID") from error
    if str(parsed) != value:
        raise ConfigurationError("runId must be a canonical UUID")
    return value


def endpoint(value: Any) -> tuple[str, str]:
    if not isinstance(value, str) or len(value) > 512:
        raise ConfigurationError("endpointUrl is invalid")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port not in (None, 443)
        or parsed.path != "/v1/h3-action"
        or parsed.query
        or parsed.fragment
        or not parsed.hostname
        or parsed.hostname != parsed.hostname.lower()
        or not DNS_NAME_PATTERN.fullmatch(parsed.hostname)
    ):
        raise ConfigurationError("endpointUrl must be canonical owned HTTPS action URL")
    canonical = f"https://{parsed.hostname}/v1/h3-action"
    if value != canonical:
        raise ConfigurationError("endpointUrl must use canonical URL form")
    return parsed.hostname, parsed.path


def pinned_address(value: Any, family: str) -> str:
    if not isinstance(value, str) or value != value.lower():
        raise ConfigurationError("pinnedAddress must be lowercase canonical text")
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError as error:
        raise ConfigurationError("pinnedAddress is invalid") from error
    expected_version = 4 if family == "ipv4" else 6
    if parsed.version != expected_version or str(parsed) != value or not parsed.is_global:
        raise ConfigurationError("pinnedAddress must be canonical public address of the declared family")
    if parsed.version == 6 and parsed.ipv4_mapped is not None:
        raise ConfigurationError("IPv4-mapped IPv6 is not native IPv6")
    return value


def bounded_integer(value: Any, minimum: int, maximum: int, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum or value > maximum:
        raise ConfigurationError(f"{name} is outside its bound")
    return value


def validate(value: dict[str, Any]) -> dict[str, Any]:
    common = {
        "scopeConfirmation",
        "endpointUrl",
        "pinnedAddress",
        "addressFamily",
        "runId",
        "testId",
        "caseId",
        "canarySource",
        "connectTimeoutSeconds",
        "ioTimeoutSeconds",
        "maxResponseBytes",
    }
    source = value.get("canarySource")
    if source == "controller-public-canary":
        exact_keys(value, common | {"publicCanary"})
    elif source == "operator-secret-file":
        exact_keys(value, common | {"operatorSecretPath"})
    else:
        raise ConfigurationError("canarySource is invalid")

    if value.get("scopeConfirmation") != SCOPE_CONFIRMATION:
        raise ConfigurationError("scope confirmation is absent")
    if value.get("testId") != TEST_ID:
        raise ConfigurationError("testId is invalid")
    case_id = value.get("caseId")
    if not isinstance(case_id, str) or case_id not in CASE_FAMILIES:
        raise ConfigurationError("caseId is invalid")
    family = value.get("addressFamily")
    if family not in ("ipv4", "ipv6"):
        raise ConfigurationError("addressFamily is invalid")
    expected_family, expected_source = CASE_FAMILIES[case_id]
    if family != expected_family or source != expected_source:
        raise ConfigurationError("case family or canary source does not match its fixed plan")

    hostname, request_path = endpoint(value.get("endpointUrl"))
    run_id = canonical_uuid(value.get("runId"))
    address = pinned_address(value.get("pinnedAddress"), family)
    connect_timeout = bounded_integer(value.get("connectTimeoutSeconds"), 2, 15, "connectTimeoutSeconds")
    io_timeout = bounded_integer(value.get("ioTimeoutSeconds"), 2, 15, "ioTimeoutSeconds")
    maximum_body = bounded_integer(value.get("maxResponseBytes"), 128, 1_024, "maxResponseBytes")

    if source == "controller-public-canary":
        public_canary = value.get("publicCanary")
        if not isinstance(public_canary, str) or not CANARY_PATTERN.fullmatch(public_canary.encode("ascii", "strict")):
            raise ConfigurationError("publicCanary is invalid")
    else:
        if value.get("operatorSecretPath") != SECRET_PATH:
            raise ConfigurationError("operatorSecretPath is not the fixed path")

    return {
        **value,
        "hostname": hostname,
        "requestPath": request_path,
        "runId": run_id,
        "pinnedAddress": address,
        "connectTimeoutSeconds": connect_timeout,
        "ioTimeoutSeconds": io_timeout,
        "maxResponseBytes": maximum_body,
    }


def plan(config: dict[str, Any]) -> dict[str, Any]:
    return {
        "ok": True,
        "phase": "plan",
        "runId": config["runId"],
        "testId": TEST_ID,
        "caseId": config["caseId"],
        "addressFamily": config["addressFamily"],
        "canarySource": config["canarySource"],
        "endpointHostname": config["hostname"],
        "pinnedAddress": config["pinnedAddress"],
        "pinnedPort": 443,
        "attemptNumber": 1,
        "maximumRequests": 1,
        "retryCount": 0,
        "redirectsAllowed": False,
        "freshConnectionRequired": True,
        "environmentProxyTrust": False,
        "strictCertificateVerification": True,
        "hostnameVerificationRequired": True,
        "secretFileValidated": False,
        "rawRequestCanaryRetained": False,
        "rawHttpResponseRetained": False,
    }


def request_canary(config: dict[str, Any]) -> tuple[bytearray, dict[str, Any]]:
    if config["canarySource"] == "controller-public-canary":
        return bytearray(config["publicCanary"], "ascii"), {
            "secretFileValidated": False,
        }

    descriptor = os.open(SECRET_PATH, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size < 24
            or metadata.st_size > 128
        ):
            raise ConfigurationError("operator secret file metadata is invalid")
        raw = bytearray(os.read(descriptor, 129))
        if len(raw) != metadata.st_size or not CANARY_PATTERN.fullmatch(bytes(raw)):
            raw[:] = b"\x00" * len(raw)
            raise ConfigurationError("operator secret file content is invalid")
        return raw, {
            "secretFileValidated": True,
            "secretFileMode": "0600",
            "secretByteLength": len(raw),
        }
    finally:
        os.close(descriptor)


class SocketReader:
    def __init__(self, stream: ssl.SSLSocket):
        self.stream = stream
        self.buffer = bytearray()

    def until(self, marker: bytes, maximum: int) -> bytes:
        while marker not in self.buffer:
            if len(self.buffer) > maximum:
                raise ValueError("HTTP header exceeds bound")
            chunk = self.stream.recv(4096)
            if not chunk:
                raise ConnectionResetError(104, "connection closed before HTTP header")
            self.buffer.extend(chunk)
        index = self.buffer.index(marker) + len(marker)
        result = bytes(self.buffer[:index])
        del self.buffer[:index]
        return result

    def exact(self, length: int) -> bytearray:
        while len(self.buffer) < length:
            chunk = self.stream.recv(min(4096, length - len(self.buffer)))
            if not chunk:
                raise ConnectionResetError(104, "connection closed before HTTP body")
            self.buffer.extend(chunk)
        result = bytearray(self.buffer[:length])
        del self.buffer[:length]
        return result

    def line(self, maximum: int = 128) -> bytes:
        return self.until(b"\r\n", maximum)[:-2]


def read_http_response(stream: ssl.SSLSocket, maximum_body: int) -> tuple[int, dict[str, str], bytearray]:
    reader = SocketReader(stream)
    raw_head = reader.until(b"\r\n\r\n", 16_384)
    lines = raw_head[:-4].split(b"\r\n")
    if not lines or not re.fullmatch(rb"HTTP/1\.[01] [0-9]{3}(?: .*)?", lines[0]):
        raise ValueError("invalid HTTP status line")
    status = int(lines[0].split(b" ", 2)[1])
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if b":" not in line:
            raise ValueError("invalid HTTP header")
        name, raw_value = line.split(b":", 1)
        decoded_name = name.decode("ascii", "strict").lower()
        decoded_value = raw_value.strip().decode("latin1", "strict")
        if decoded_name in headers:
            headers[decoded_name] += ", " + decoded_value
        else:
            headers[decoded_name] = decoded_value

    transfer_encoding = headers.get("transfer-encoding", "").lower()
    if transfer_encoding:
        if transfer_encoding != "chunked":
            raise ValueError("unsupported transfer encoding")
        body = bytearray()
        while True:
            raw_size = reader.line()
            size_text = raw_size.split(b";", 1)[0]
            size = int(size_text, 16)
            if size == 0:
                while reader.line():
                    pass
                break
            if len(body) + size > maximum_body:
                raise ValueError("HTTP response body exceeds bound")
            body.extend(reader.exact(size))
            if reader.exact(2) != b"\r\n":
                raise ValueError("invalid chunk terminator")
        return status, headers, body

    raw_length = headers.get("content-length")
    if raw_length is None or not raw_length.isdigit():
        raise ValueError("bounded response requires Content-Length or chunked encoding")
    length = int(raw_length)
    if length > maximum_body:
        raise ValueError("HTTP response body exceeds bound")
    return status, headers, reader.exact(length)


def active_block(error: BaseException) -> bool:
    return isinstance(
        error,
        (
            BrokenPipeError,
            ConnectionAbortedError,
            ConnectionRefusedError,
            ConnectionResetError,
            OSError,
            ssl.SSLEOFError,
            ssl.SSLZeroReturnError,
        ),
    ) and getattr(error, "errno", None) in {32, 54, 61, 101, 104, 111, 113}


def run(config: dict[str, Any]) -> tuple[dict[str, Any], int]:
    current_phase = "connect"
    raw_socket: socket.socket | None = None
    tls_socket: ssl.SSLSocket | None = None
    canary = bytearray()
    request = bytearray()
    response_body = bytearray()
    file_proof: dict[str, Any] = {"secretFileValidated": False}
    base = {
        "runId": config["runId"],
        "testId": TEST_ID,
        "caseId": config["caseId"],
        "addressFamily": config["addressFamily"],
        "canarySource": config["canarySource"],
        "endpointHostname": config["hostname"],
        "pinnedAddress": config["pinnedAddress"],
        "pinnedPort": 443,
        "attemptNumber": 1,
        "maximumRequests": 1,
        "retryCount": 0,
        "redirectsAllowed": False,
        "freshConnectionRequired": True,
        "environmentProxyTrust": False,
        "strictCertificateVerification": True,
        "hostnameVerificationRequired": True,
    }
    try:
        canary, file_proof = request_canary(config)
        query = (
            b"?run=" + config["runId"].encode("ascii")
            + b"&case=" + config["caseId"].encode("ascii")
            + b"&canary=" + bytes(canary)
        )
        request.extend(
            b"GET " + config["requestPath"].encode("ascii") + query + b" HTTP/1.1\r\n"
            + b"Host: " + config["hostname"].encode("ascii") + b"\r\n"
            + b"User-Agent: vsc-native-ipv6-deny-probe/1\r\n"
            + b"Accept: application/json\r\n"
            + b"Connection: close\r\n\r\n"
        )

        family = socket.AF_INET if config["addressFamily"] == "ipv4" else socket.AF_INET6
        destination: tuple[Any, ...] = (
            (config["pinnedAddress"], 443)
            if family == socket.AF_INET
            else (config["pinnedAddress"], 443, 0, 0)
        )
        raw_socket = socket.socket(family, socket.SOCK_STREAM)
        raw_socket.settimeout(config["connectTimeoutSeconds"])
        raw_socket.connect(destination)
        raw_socket.settimeout(config["ioTimeoutSeconds"])

        current_phase = "handshake"
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.set_alpn_protocols(["http/1.1"])
        tls_socket = context.wrap_socket(raw_socket, server_hostname=config["hostname"])
        raw_socket = None
        if tls_socket.selected_alpn_protocol() != "http/1.1":
            raise ssl.SSLError("endpoint did not negotiate required HTTP/1.1 ALPN")
        peer = tls_socket.getpeername()
        peer_address = str(ipaddress.ip_address(peer[0]))
        if peer_address != config["pinnedAddress"]:
            raise ssl.SSLError("connected peer does not match the pinned address")
        peer_family = "ipv4" if tls_socket.family == socket.AF_INET else "ipv6"
        if peer_family != config["addressFamily"]:
            raise ssl.SSLError("connected peer family does not match the configured family")
        certificate = tls_socket.getpeercert(binary_form=True)
        if not certificate:
            raise ssl.SSLError("peer certificate is absent")

        current_phase = "write"
        tls_socket.sendall(request)
        current_phase = "read"
        status_code, headers, response_body = read_http_response(tls_socket, config["maxResponseBytes"])
        current_phase = "response"
        try:
            payload = json.loads(response_body)
        except Exception as error:
            raise ValueError("action response is not valid JSON") from error
        if not isinstance(payload, dict):
            raise ValueError("action response is not an object")
        operation_id = payload.get("operationId")
        authorized = payload.get("authorized")
        cipher = tls_socket.cipher()
        result = {
            **base,
            "ok": True,
            "phase": "response",
            "certificateVerified": True,
            "hostnameVerified": True,
            "selectedAlpn": tls_socket.selected_alpn_protocol(),
            "tlsVersion": tls_socket.version(),
            "cipherSuite": cipher[0] if cipher else None,
            "peerCertificateSha256": hashlib.sha256(certificate).hexdigest(),
            "peerAddress": peer_address,
            "peerAddressFamily": peer_family,
            "peerPort": peer[1],
            "nativeIpv6": peer_family == "ipv6" and not peer_address.lower().startswith("::ffff:"),
            **file_proof,
            "response": {
                "statusCode": status_code,
                "contentType": headers.get("content-type"),
                "cacheControl": headers.get("cache-control"),
                "bodyByteLength": len(response_body),
                "bodyContainsCanary": bytes(canary) in response_body,
                "rawBodyRetained": False,
            },
            "authorized": authorized if isinstance(authorized, bool) else None,
            "operationId": operation_id if isinstance(operation_id, str) else None,
            "operationIdShapeValid": isinstance(operation_id, str)
            and OPERATION_ID_PATTERN.fullmatch(operation_id) is not None,
        }
        return result, 0
    except (socket.timeout, TimeoutError) as error:
        return {
            **base,
            "ok": False,
            "phase": current_phase,
            **file_proof,
            "errorType": type(error).__name__,
            "timeout": True,
            "responseStatusCode": 0,
        }, 20
    except BaseException as error:
        errno = getattr(error, "errno", None)
        result = {
            **base,
            "ok": False,
            "phase": current_phase,
            **file_proof,
            "errorType": type(error).__name__,
            "errorErrno": errno if isinstance(errno, int) else None,
            "errorSyscall": current_phase,
            "timeout": False,
            "responseStatusCode": 0,
        }
        return result, 10 if active_block(error) else 20
    finally:
        if response_body:
            response_body[:] = b"\x00" * len(response_body)
        if request:
            request[:] = b"\x00" * len(request)
        if canary:
            canary[:] = b"\x00" * len(canary)
        if tls_socket is not None:
            try:
                tls_socket.close()
            except OSError:
                pass
        if raw_socket is not None:
            try:
                raw_socket.close()
            except OSError:
                pass


def main() -> int:
    if len(sys.argv) not in (2, 3):
        emit({"ok": False, "phase": "configuration", "errorType": "ConfigurationError"})
        return 20
    try:
        config = validate(decode_configuration(sys.argv[1]))
        if len(sys.argv) == 3:
            if sys.argv[2] != "--plan":
                raise ConfigurationError("unknown mode")
            emit(plan(config))
            return 0
        result, exit_code = run(config)
        emit(result)
        return exit_code
    except BaseException as error:
        emit({
            "ok": False,
            "phase": "configuration",
            "errorType": type(error).__name__,
            "timeout": False,
            "responseStatusCode": 0,
        })
        return 20


if __name__ == "__main__":
    raise SystemExit(main())
