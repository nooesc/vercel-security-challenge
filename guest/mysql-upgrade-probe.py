#!/usr/bin/env python3
"""One-shot, bounded MySQL server-first/TLS-upgrade probe for SBX-039.

MySQL is server-first. The target modes wait for a valid, case-bound
HandshakeV10 packet, then send a standards-shaped 32-byte MySQL SSLRequest
followed by a real TLS ClientHello. The public canary or file-backed synthetic
secret is encoded in the denied SNI label. Raw values are never printed.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import os
import re
import socket
import ssl
import stat
import struct
import sys
import time
from typing import Any


TEST_ID = "SBX-039-POC"
SCOPE_CONFIRMATION = (
    "I_CONTROL_DISTINCT_ALLOWED_AND_DENIED_ENDPOINTS_AND_AUTHORIZE_BOUNDED_MYSQL_PRETLS_TESTING"
)
SECRET_PATH = "/tmp/sbx-039/operator-secret"
CLIENT_SSL = 0x00000800
CLIENT_PROTOCOL_41 = 0x00000200
CLIENT_SECURE_CONNECTION = 0x00008000
CLIENT_PLUGIN_AUTH = 0x00080000
CLIENT_FLAGS = CLIENT_SSL | CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH
SSL_REQUEST_PAYLOAD = struct.pack("<IIB23s", CLIENT_FLAGS, 16 * 1024 * 1024, 0x2D, b"\x00" * 23)
SSL_REQUEST = len(SSL_REQUEST_PAYLOAD).to_bytes(3, "little") + b"\x01" + SSL_REQUEST_PAYLOAD
RAW_MAGIC = b"SBX039R1"
MAX_CLIENT_HELLO_BYTES = 16_384
MAX_RESPONSE_BYTES = 2_048
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
CASE_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
DNS_NAME = re.compile(
    r"^(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
HEX32 = re.compile(r"^[a-f0-9]{32}$")
GREETING_TAG = re.compile(r"^[A-Za-z0-9_-]{16}$")
MODES = frozenset(
    (
        "https-control",
        "direct-tls",
        "raw-public",
        "greeting-only",
        "mysql-split-public",
        "mysql-coalesced-public",
        "mysql-coalesced-secret",
    )
)
ALLOWED_KEYS = frozenset(
    (
        "scopeConfirmation",
        "mode",
        "runId",
        "testId",
        "caseId",
        "endpointRole",
        "endpointHostname",
        "pinnedIPv4",
        "pinnedPort",
        "publicCanary",
        "greetingTag",
        "timeoutMs",
        "maxResponseBytes",
    )
)


class ConfigurationError(ValueError):
    pass


def _bounded_int(value: Any, field: str, minimum: int, maximum: int, fallback: int) -> int:
    selected = fallback if value is None else value
    if isinstance(selected, bool) or not isinstance(selected, int) or not minimum <= selected <= maximum:
        raise ConfigurationError(f"{field} must be an integer from {minimum} through {maximum}")
    return selected


def _canonical_hostname(value: Any) -> str:
    if not isinstance(value, str) or value != value.strip():
        raise ConfigurationError("endpointHostname must be canonical")
    try:
        canonical = value.encode("idna").decode("ascii").lower()
    except UnicodeError as error:
        raise ConfigurationError("endpointHostname must be DNS") from error
    if canonical != value or DNS_NAME.fullmatch(canonical) is None:
        raise ConfigurationError("endpointHostname must be a lowercase DNS hostname")
    return canonical


def _public_ipv4(value: Any) -> str:
    try:
        address = ipaddress.IPv4Address(value)
    except (ipaddress.AddressValueError, TypeError):
        raise ConfigurationError("pinnedIPv4 must be one canonical IPv4 address") from None
    if not address.is_global or str(address) != value:
        raise ConfigurationError("pinnedIPv4 must be one canonical public IPv4 address")
    return str(address)


def validate_configuration(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConfigurationError("configuration must be an object")
    unknown = sorted(set(value) - ALLOWED_KEYS)
    if unknown:
        raise ConfigurationError(f"configuration field {json.dumps(unknown[0])} is not allowed")
    if value.get("scopeConfirmation") != SCOPE_CONFIRMATION or value.get("testId") != TEST_ID:
        raise ConfigurationError("scopeConfirmation or testId is not exact")
    mode = value.get("mode")
    run_id = value.get("runId")
    case_id = value.get("caseId")
    role = value.get("endpointRole")
    if mode not in MODES:
        raise ConfigurationError("mode is not one fixed SBX-039 mode")
    if not isinstance(run_id, str) or UUID.fullmatch(run_id) is None:
        raise ConfigurationError("runId must be a canonical random UUID")
    if not isinstance(case_id, str) or CASE_ID.fullmatch(case_id) is None:
        raise ConfigurationError("caseId must be a bounded lowercase identifier")
    if role not in ("allowed", "denied") or (mode == "https-control") != (role == "allowed"):
        raise ConfigurationError("only https-control may target the allowed role")
    hostname = _canonical_hostname(value.get("endpointHostname"))
    port = _bounded_int(value.get("pinnedPort"), "pinnedPort", 1, 65535, 3306)
    if mode == "https-control" and port != 443:
        raise ConfigurationError("https-control is fixed to port 443")
    ipv4 = None if mode == "https-control" else _public_ipv4(value.get("pinnedIPv4"))
    public_canary = value.get("publicCanary")
    public_mode = mode in ("direct-tls", "raw-public", "mysql-split-public", "mysql-coalesced-public")
    if public_mode:
        if not isinstance(public_canary, str) or HEX32.fullmatch(public_canary) is None:
            raise ConfigurationError("public mode requires one 32-hex canary")
    elif "publicCanary" in value:
        raise ConfigurationError("this mode may not receive a public canary")
    greeting_tag = value.get("greetingTag")
    greeting_mode = mode in ("greeting-only", "mysql-split-public", "mysql-coalesced-public", "mysql-coalesced-secret")
    if greeting_mode:
        if not isinstance(greeting_tag, str) or GREETING_TAG.fullmatch(greeting_tag) is None:
            raise ConfigurationError("MySQL server-first mode requires one exact greetingTag")
    elif "greetingTag" in value:
        raise ConfigurationError("this mode may not receive a greetingTag")
    server_name_prefix = "s39s-" if mode == "mysql-coalesced-secret" else "s39p-"
    if mode != "https-control" and len(server_name_prefix) + 32 + 1 + len(hostname) > 253:
        raise ConfigurationError("derived proof SNI would exceed the DNS bound")
    return {
        "mode": mode,
        "runId": run_id,
        "testId": TEST_ID,
        "caseId": case_id,
        "endpointRole": role,
        "endpointHostname": hostname,
        **({"pinnedIPv4": ipv4} if ipv4 is not None else {}),
        "pinnedPort": port,
        **({"publicCanary": public_canary} if public_mode else {}),
        **({"greetingTag": greeting_tag} if greeting_mode else {}),
        "timeoutMs": _bounded_int(value.get("timeoutMs"), "timeoutMs", 250, 8000, 3000),
        "maxResponseBytes": _bounded_int(value.get("maxResponseBytes"), "maxResponseBytes", 64, MAX_RESPONSE_BYTES, 512),
    }


def decode_argument(raw: str) -> Any:
    if len(raw) > 16_384 or re.fullmatch(r"[A-Za-z0-9_-]+", raw) is None:
        raise ConfigurationError("configuration argument is not bounded base64url")
    padded = raw + "=" * ((4 - len(raw) % 4) % 4)
    try:
        decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
        if len(decoded) > 8192:
            raise ConfigurationError("configuration JSON exceeded its bound")
        return json.loads(decoded)
    except (ValueError, UnicodeError, json.JSONDecodeError) as error:
        raise ConfigurationError("configuration argument is invalid") from error


def base_result(config: dict[str, Any]) -> dict[str, Any]:
    return {
        "ok": True,
        "phase": "planned",
        "mode": config["mode"],
        "runId": config["runId"],
        "testId": TEST_ID,
        "caseId": config["caseId"],
        "endpointRole": config["endpointRole"],
        "endpointHostname": config["endpointHostname"],
        **({"pinnedIPv4": config["pinnedIPv4"]} if "pinnedIPv4" in config else {}),
        "pinnedPort": config["pinnedPort"],
        "attemptCount": 1,
        "retryCount": 0,
        "tcpConnected": False,
        "validGreetingReceived": False,
        "greetingTagMatched": False,
        "sslRequestExact": SSL_REQUEST_PAYLOAD.__len__() == 32 and SSL_REQUEST.__len__() == 36,
        "sslRequestBytes": 0,
        "clientHelloGenerated": False,
        "clientHelloSent": False,
        "clientHelloBytes": 0,
        "explicitSocketWriteCount": 0,
        "interWriteDelayMs": 0,
        "operatorSecretFileValidated": False,
        "receivedResponse": False,
        "timedOut": False,
        "rawConfigurationRetained": False,
        "rawServerNameRetained": False,
        "rawOperatorSecretRetained": False,
    }


def safe_error_code(error: BaseException) -> str:
    if isinstance(error, socket.timeout):
        return "ETIMEDOUT"
    if isinstance(error, ssl.SSLError):
        return "TLS_REJECTED"
    if isinstance(error, socket.gaierror):
        return "EAI_AGAIN"
    if isinstance(error, OSError) and error.errno is not None:
        return {
            32: "EPIPE",
            54: "ECONNRESET",
            61: "ECONNREFUSED",
            65: "EHOSTUNREACH",
            104: "ECONNRESET",
            111: "ECONNREFUSED",
            113: "EHOSTUNREACH",
        }.get(error.errno, f"ERRNO_{error.errno}")
    return error.__class__.__name__[:64]


def receive_exact(sock: socket.socket, length: int) -> bytes:
    output = bytearray()
    while len(output) < length:
        chunk = sock.recv(length - len(output))
        if not chunk:
            raise ConnectionResetError("socket closed during bounded receive")
        output.extend(chunk)
    return bytes(output)


def receive_mysql_greeting(sock: socket.socket, expected_tag: str) -> tuple[bool, int]:
    header = receive_exact(sock, 4)
    payload_length = int.from_bytes(header[:3], "little")
    if header[3] != 0 or payload_length < 48 or payload_length > 512:
        raise ValueError("server greeting packet header was invalid")
    payload = receive_exact(sock, payload_length)
    if payload[0] != 10:
        raise ValueError("server greeting was not HandshakeV10")
    nul = payload.find(b"\x00", 1, 128)
    if nul < 0:
        raise ValueError("server greeting version was unterminated")
    version = payload[1:nul].decode("ascii", "strict")
    if version != f"8.0.0-sbx039-{expected_tag}":
        raise ValueError("server greeting tag did not match this case")
    offset = nul + 1
    if len(payload) < offset + 4 + 8 + 1 + 2 + 1 + 2 + 2:
        raise ValueError("server greeting was truncated")
    lower = struct.unpack_from("<H", payload, offset + 13)[0]
    upper = struct.unpack_from("<H", payload, offset + 18)[0]
    capabilities = lower | (upper << 16)
    if capabilities & (CLIENT_SSL | CLIENT_PROTOCOL_41) != (CLIENT_SSL | CLIENT_PROTOCOL_41):
        raise ValueError("server greeting did not offer CLIENT_SSL and CLIENT_PROTOCOL_41")
    return True, len(header) + len(payload)


def make_client_hello(server_name: str) -> bytearray:
    context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    incoming = ssl.MemoryBIO()
    outgoing = ssl.MemoryBIO()
    tls = context.wrap_bio(incoming, outgoing, server_side=False, server_hostname=server_name)
    try:
        tls.do_handshake()
    except ssl.SSLWantReadError:
        pass
    flight = bytearray()
    while outgoing.pending:
        flight.extend(outgoing.read())
    if not 9 <= len(flight) <= MAX_CLIENT_HELLO_BYTES or flight[0] != 0x16 or flight[1] != 0x03:
        raise ValueError("MemoryBIO did not produce a bounded TLS ClientHello flight")
    return flight


def read_secret_server_name(config: dict[str, Any]) -> tuple[str, bytearray, int]:
    file_stat = os.stat(SECRET_PATH, follow_symlinks=False)
    mode = stat.S_IMODE(file_stat.st_mode)
    if not stat.S_ISREG(file_stat.st_mode) or mode != 0o600:
        raise ValueError("operator secret file must be regular mode 0600")
    raw = bytearray(open(SECRET_PATH, "rb", buffering=0).read(64))
    if len(raw) != 32:
        for index in range(len(raw)):
            raw[index] = 0
        raise ValueError("operator secret must contain exactly 32 bytes")
    try:
        text = raw.decode("ascii", "strict")
        if HEX32.fullmatch(text) is None:
            raise ValueError("operator secret must be exactly 32 lowercase hex characters")
        return f"s39s-{text}.{config['endpointHostname']}", raw, mode
    except BaseException:
        for index in range(len(raw)):
            raw[index] = 0
        raise


def public_server_name(config: dict[str, Any]) -> str:
    return f"s39p-{config['publicCanary']}.{config['endpointHostname']}"


def maybe_receive(sock: socket.socket, maximum: int) -> bool:
    try:
        return bool(sock.recv(maximum))
    except (socket.timeout, ConnectionResetError, OSError):
        return False


def run_https(config: dict[str, Any]) -> tuple[dict[str, Any], int]:
    result = base_result(config)
    raw: socket.socket | None = None
    wrapped: ssl.SSLSocket | None = None
    started = time.monotonic()
    try:
        raw = socket.create_connection(
            (config["endpointHostname"], 443), timeout=config["timeoutMs"] / 1000
        )
        result["tcpConnected"] = True
        raw.settimeout(config["timeoutMs"] / 1000)
        context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        wrapped = context.wrap_socket(raw, server_hostname=config["endpointHostname"])
        raw = None
        request = (
            f"GET /healthz HTTP/1.1\r\nHost: {config['endpointHostname']}\r\n"
            "Connection: close\r\nAccept: application/json\r\n\r\n"
        ).encode("ascii")
        wrapped.sendall(request)
        result["explicitSocketWriteCount"] = 1
        response = bytearray()
        while len(response) < config["maxResponseBytes"] and b"\r\n" not in response:
            chunk = wrapped.recv(min(512, config["maxResponseBytes"] - len(response)))
            if not chunk:
                break
            response.extend(chunk)
        status_line = bytes(response).split(b"\r\n", 1)[0]
        response[:] = b"\x00" * len(response)
        match = re.fullmatch(rb"HTTP/1\.[01] ([0-9]{3}) [^\r\n]{0,128}", status_line)
        if match is None:
            raise ValueError("HTTPS response status line was invalid")
        result.update(
            {
                "phase": "complete",
                "receivedResponse": True,
                "statusCode": int(match.group(1)),
                "durationMs": round((time.monotonic() - started) * 1000),
            }
        )
        return result, 0
    except BaseException as error:
        code = safe_error_code(error)
        result.update(
            {
                "phase": "blocked" if result["tcpConnected"] is False else "handshake",
                "errorCode": code,
                "timedOut": code == "ETIMEDOUT",
                "durationMs": round((time.monotonic() - started) * 1000),
            }
        )
        return result, 0
    finally:
        for candidate in (wrapped, raw):
            if candidate is not None:
                try:
                    candidate.close()
                except OSError:
                    pass


def run_direct_or_raw(config: dict[str, Any]) -> tuple[dict[str, Any], int]:
    result = base_result(config)
    sock: socket.socket | None = None
    transmission: bytearray | None = None
    started = time.monotonic()
    try:
        server_name = public_server_name(config)
        result["serverNameKind"] = "public"
        if config["mode"] == "direct-tls":
            transmission = make_client_hello(server_name)
            result["clientHelloGenerated"] = True
            result["clientHelloBytes"] = len(transmission)
        else:
            server_name_bytes = server_name.encode("ascii")
            transmission = bytearray(RAW_MAGIC + struct.pack("!H", len(server_name_bytes)) + server_name_bytes)
        sock = socket.create_connection(
            (config["pinnedIPv4"], config["pinnedPort"]), timeout=config["timeoutMs"] / 1000
        )
        result["tcpConnected"] = True
        sock.settimeout(min(config["timeoutMs"] / 1000, 0.75))
        sock.sendall(transmission)
        result["explicitSocketWriteCount"] = 1
        if config["mode"] == "direct-tls":
            result["clientHelloSent"] = True
        transmission[:] = b"\x00" * len(transmission)
        result["receivedResponse"] = maybe_receive(sock, config["maxResponseBytes"])
        result.update({"phase": "sent", "durationMs": round((time.monotonic() - started) * 1000)})
        return result, 0
    except BaseException as error:
        code = safe_error_code(error)
        result.update(
            {
                "phase": "blocked" if result["tcpConnected"] is False else "send",
                "errorCode": code,
                "timedOut": code == "ETIMEDOUT",
                "durationMs": round((time.monotonic() - started) * 1000),
            }
        )
        return result, 0
    finally:
        if transmission is not None:
            transmission[:] = b"\x00" * len(transmission)
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def run_mysql(config: dict[str, Any]) -> tuple[dict[str, Any], int]:
    result = base_result(config)
    sock: socket.socket | None = None
    secret_bytes: bytearray | None = None
    hello: bytearray | None = None
    transmission: bytearray | None = None
    started = time.monotonic()
    try:
        sock = socket.create_connection(
            (config["pinnedIPv4"], config["pinnedPort"]), timeout=config["timeoutMs"] / 1000
        )
        result["tcpConnected"] = True
        sock.settimeout(config["timeoutMs"] / 1000)
        valid, greeting_bytes = receive_mysql_greeting(sock, config["greetingTag"])
        result["validGreetingReceived"] = valid
        result["greetingTagMatched"] = valid
        result["receivedResponse"] = greeting_bytes > 0
        if config["mode"] == "greeting-only":
            result.update({"phase": "complete", "durationMs": round((time.monotonic() - started) * 1000)})
            return result, 0
        if config["mode"] == "mysql-coalesced-secret":
            server_name, secret_bytes, secret_mode = read_secret_server_name(config)
            result["serverNameKind"] = "secret"
            result["operatorSecretFileValidated"] = True
            result["operatorSecretFileMode"] = secret_mode
            result["secretReadAfterGreeting"] = True
        else:
            server_name = public_server_name(config)
            result["serverNameKind"] = "public"
        hello = make_client_hello(server_name)
        result["clientHelloGenerated"] = True
        result["clientHelloBytes"] = len(hello)
        result["sslRequestBytes"] = len(SSL_REQUEST)
        if config["mode"] == "mysql-split-public":
            sock.sendall(SSL_REQUEST)
            result["explicitSocketWriteCount"] = 1
            result["interWriteDelayMs"] = 250
            time.sleep(0.25)
            sock.sendall(hello)
            result["explicitSocketWriteCount"] = 2
        else:
            transmission = bytearray(SSL_REQUEST)
            transmission.extend(hello)
            sock.sendall(transmission)
            result["explicitSocketWriteCount"] = 1
            transmission[:] = b"\x00" * len(transmission)
        result["clientHelloSent"] = True
        hello[:] = b"\x00" * len(hello)
        if secret_bytes is not None:
            secret_bytes[:] = b"\x00" * len(secret_bytes)
        result["receivedResponse"] = maybe_receive(sock, config["maxResponseBytes"]) or result["receivedResponse"]
        result.update({"phase": "sent", "durationMs": round((time.monotonic() - started) * 1000)})
        return result, 0
    except BaseException as error:
        code = safe_error_code(error)
        result.update(
            {
                "phase": "blocked" if result["tcpConnected"] is False else "greeting-or-send",
                "errorCode": code,
                "timedOut": code == "ETIMEDOUT",
                "durationMs": round((time.monotonic() - started) * 1000),
            }
        )
        return result, 0
    finally:
        for value in (transmission, hello, secret_bytes):
            if value is not None:
                value[:] = b"\x00" * len(value)
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def plan(config: dict[str, Any]) -> dict[str, Any]:
    result = base_result(config)
    result.update(
        {
            "phase": "plan",
            "maximumNetworkAttempts": 1,
            "maximumClientHelloBytes": MAX_CLIENT_HELLO_BYTES,
            "strictHttpsCertificateVerification": config["mode"] == "https-control",
            "secretPathFixed": config["mode"] == "mysql-coalesced-secret",
            "serverFirstGreetingRequired": config["mode"].startswith("mysql-") or config["mode"] == "greeting-only",
        }
    )
    return result


def main() -> int:
    if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] != "--plan"):
        print(json.dumps({"ok": False, "phase": "configuration", "errorCode": "ARGUMENTS"}))
        return 20
    try:
        config = validate_configuration(decode_argument(sys.argv[1]))
        if len(sys.argv) == 3:
            result, exit_code = plan(config), 0
        elif config["mode"] == "https-control":
            result, exit_code = run_https(config)
        elif config["mode"] in ("direct-tls", "raw-public"):
            result, exit_code = run_direct_or_raw(config)
        else:
            result, exit_code = run_mysql(config)
    except BaseException as error:
        result = {
            "ok": False,
            "phase": "configuration",
            "errorCode": error.__class__.__name__[:64],
            "rawConfigurationRetained": False,
            "rawServerNameRetained": False,
            "rawOperatorSecretRetained": False,
        }
        exit_code = 20
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
