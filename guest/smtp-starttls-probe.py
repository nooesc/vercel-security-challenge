#!/usr/bin/env python3
"""One-attempt SMTP STARTTLS pre-authorization probe for SBX-043.

The SMTP modes require a case-bound server greeting before reading or sending
the proof value. Public proof and a fixed-path mode-0600 synthetic file secret
are encoded in one standards-bounded EHLO argument. Raw proof values and SMTP
transcripts are never printed.
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


TEST_ID = "SBX-043-POC"
SCOPE_CONFIRMATION = (
    "I_CONTROL_DISTINCT_ALLOWED_AND_DENIED_ENDPOINTS_AND_AUTHORIZE_BOUNDED_SMTP_STARTTLS_TESTING"
)
SECRET_PATH = "/tmp/sbx-043/operator-secret"
RAW_MAGIC = b"SBX043R1"
MAX_RESPONSE_BYTES = 4096
MAX_CLIENT_HELLO_BYTES = 16384
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
CASE_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
DNS_NAME = re.compile(
    r"^(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
HEX32 = re.compile(r"^[a-f0-9]{32}$")
GREETING_TAG = re.compile(r"^[A-Za-z0-9_-]{16}$")
MODES = frozenset((
    "https-control",
    "direct-tls",
    "raw-public",
    "smtp-starttls-public",
    "smtp-starttls-secret",
))
ALLOWED_KEYS = frozenset((
    "scopeConfirmation", "mode", "runId", "testId", "caseId", "endpointRole",
    "endpointHostname", "pinnedIPv4", "pinnedPort", "publicCanary",
    "greetingTag", "timeoutMs", "maxResponseBytes",
))


class ConfigurationError(ValueError):
    pass


def bounded_int(value: Any, field: str, minimum: int, maximum: int, fallback: int) -> int:
    selected = fallback if value is None else value
    if isinstance(selected, bool) or not isinstance(selected, int) or not minimum <= selected <= maximum:
        raise ConfigurationError(f"{field} must be an integer from {minimum} through {maximum}")
    return selected


def canonical_hostname(value: Any) -> str:
    if not isinstance(value, str) or value != value.strip():
        raise ConfigurationError("endpointHostname must be canonical")
    try:
        canonical = value.encode("idna").decode("ascii").lower()
    except UnicodeError as error:
        raise ConfigurationError("endpointHostname must be DNS") from error
    if canonical != value or DNS_NAME.fullmatch(canonical) is None:
        raise ConfigurationError("endpointHostname must be a lowercase DNS hostname")
    return canonical


def public_ipv4(value: Any) -> str:
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
        raise ConfigurationError("mode is not one fixed SBX-043 mode")
    if not isinstance(run_id, str) or UUID.fullmatch(run_id) is None:
        raise ConfigurationError("runId must be a canonical random UUID")
    if not isinstance(case_id, str) or CASE_ID.fullmatch(case_id) is None:
        raise ConfigurationError("caseId must be a bounded lowercase identifier")
    if role not in ("allowed", "denied") or (mode == "https-control") != (role == "allowed"):
        raise ConfigurationError("only https-control may target the allowed role")
    hostname = canonical_hostname(value.get("endpointHostname"))
    port = bounded_int(value.get("pinnedPort"), "pinnedPort", 1, 65535, 587)
    if mode == "https-control" and port != 443:
        raise ConfigurationError("https-control is fixed to port 443")
    ipv4 = None if mode == "https-control" else public_ipv4(value.get("pinnedIPv4"))
    public_canary = value.get("publicCanary")
    public_mode = mode in ("direct-tls", "raw-public", "smtp-starttls-public")
    if public_mode:
        if not isinstance(public_canary, str) or HEX32.fullmatch(public_canary) is None:
            raise ConfigurationError("public mode requires one 32-hex canary")
    elif "publicCanary" in value:
        raise ConfigurationError("this mode may not receive a public canary")
    greeting_tag = value.get("greetingTag")
    smtp_mode = mode in ("smtp-starttls-public", "smtp-starttls-secret")
    if smtp_mode:
        if not isinstance(greeting_tag, str) or GREETING_TAG.fullmatch(greeting_tag) is None:
            raise ConfigurationError("SMTP mode requires one exact greetingTag")
    elif "greetingTag" in value:
        raise ConfigurationError("this mode may not receive a greetingTag")
    proof_prefix = "s43s-" if mode == "smtp-starttls-secret" else "s43p-"
    if mode != "https-control" and len(proof_prefix) + 32 + 1 + len(hostname) > 253:
        raise ConfigurationError("derived proof hostname would exceed the DNS bound")
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
        **({"greetingTag": greeting_tag} if smtp_mode else {}),
        "timeoutMs": bounded_int(value.get("timeoutMs"), "timeoutMs", 250, 8000, 3000),
        "maxResponseBytes": bounded_int(value.get("maxResponseBytes"), "maxResponseBytes", 64, MAX_RESPONSE_BYTES, 1024),
    }


def decode_argument(raw: str) -> Any:
    if len(raw) > 16384 or re.fullmatch(r"[A-Za-z0-9_-]+", raw) is None:
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
        "ehloSent": False,
        "ehloBytes": 0,
        "startTlsAdvertised": False,
        "startTlsCommandSent": False,
        "startTlsReadyReceived": False,
        "clientHelloGenerated": False,
        "clientHelloSent": False,
        "tlsHandshakeComplete": False,
        "peerCertificateVerified": False,
        "postTlsEhloComplete": False,
        "explicitSocketWriteCount": 0,
        "operatorSecretFileValidated": False,
        "receivedResponse": False,
        "timedOut": False,
        "rawConfigurationRetained": False,
        "rawEhloRetained": False,
        "rawOperatorSecretRetained": False,
    }


def safe_error_code(error: BaseException) -> str:
    if isinstance(error, socket.timeout):
        return "ETIMEDOUT"
    if isinstance(error, ssl.SSLCertVerificationError):
        return "CERTIFICATE_REJECTED"
    if isinstance(error, ssl.SSLError):
        return "TLS_REJECTED"
    if isinstance(error, socket.gaierror):
        return "EAI_AGAIN"
    if isinstance(error, OSError) and error.errno is not None:
        return {32: "EPIPE", 54: "ECONNRESET", 61: "ECONNREFUSED", 65: "EHOSTUNREACH",
                104: "ECONNRESET", 111: "ECONNREFUSED", 113: "EHOSTUNREACH"}.get(
                    error.errno, f"ERRNO_{error.errno}"
                )
    return error.__class__.__name__[:64]


def receive_smtp_reply(sock: socket.socket, expected_code: int, maximum: int) -> list[bytes]:
    data = bytearray()
    lines: list[bytes] = []
    while len(data) < maximum and len(lines) < 32:
        chunk = sock.recv(min(512, maximum - len(data)))
        if not chunk:
            raise ConnectionResetError("socket closed during SMTP response")
        data.extend(chunk)
        while b"\r\n" in data:
            line, remainder = data.split(b"\r\n", 1)
            data[:] = remainder
            if len(line) < 4 or not line[:3].isdigit() or int(line[:3]) != expected_code or line[3:4] not in (b"-", b" "):
                raise ValueError("SMTP response line was invalid")
            lines.append(bytes(line))
            if line[3:4] == b" ":
                data[:] = b"\x00" * len(data)
                return lines
    data[:] = b"\x00" * len(data)
    raise ValueError("SMTP response exceeded its bound")


def make_client_hello(server_name: str) -> bytearray:
    context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
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
        raise ValueError("MemoryBIO did not produce a bounded TLS ClientHello")
    return flight


def public_proof_name(config: dict[str, Any]) -> str:
    return f"s43p-{config['publicCanary']}.{config['endpointHostname']}"


def read_secret_proof_name(config: dict[str, Any]) -> tuple[str, bytearray, int]:
    file_stat = os.stat(SECRET_PATH, follow_symlinks=False)
    mode = stat.S_IMODE(file_stat.st_mode)
    if not stat.S_ISREG(file_stat.st_mode) or mode != 0o600:
        raise ValueError("operator secret file must be regular mode 0600")
    raw = bytearray(open(SECRET_PATH, "rb", buffering=0).read(64))
    if len(raw) != 32:
        raw[:] = b"\x00" * len(raw)
        raise ValueError("operator secret must contain exactly 32 bytes")
    try:
        text = raw.decode("ascii", "strict")
        if HEX32.fullmatch(text) is None:
            raise ValueError("operator secret must be exactly 32 lowercase hex characters")
        return f"s43s-{text}.{config['endpointHostname']}", raw, mode
    except BaseException:
        raw[:] = b"\x00" * len(raw)
        raise


def run_https(config: dict[str, Any]) -> tuple[dict[str, Any], int]:
    result = base_result(config)
    raw: socket.socket | None = None
    wrapped: ssl.SSLSocket | None = None
    started = time.monotonic()
    try:
        raw = socket.create_connection((config["endpointHostname"], 443), timeout=config["timeoutMs"] / 1000)
        result["tcpConnected"] = True
        raw.settimeout(config["timeoutMs"] / 1000)
        context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        wrapped = context.wrap_socket(raw, server_hostname=config["endpointHostname"])
        raw = None
        request = (f"GET /healthz HTTP/1.1\r\nHost: {config['endpointHostname']}\r\n"
                   "Connection: close\r\nAccept: application/json\r\n\r\n").encode("ascii")
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
        result.update({"phase": "complete", "receivedResponse": True, "statusCode": int(match.group(1)),
                       "durationMs": round((time.monotonic() - started) * 1000)})
        return result, 0
    except BaseException as error:
        code = safe_error_code(error)
        result.update({"phase": "blocked" if not result["tcpConnected"] else "handshake", "errorCode": code,
                       "timedOut": code == "ETIMEDOUT", "durationMs": round((time.monotonic() - started) * 1000)})
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
        proof_name = public_proof_name(config)
        if config["mode"] == "direct-tls":
            transmission = make_client_hello(proof_name)
            result["clientHelloGenerated"] = True
        else:
            encoded = proof_name.encode("ascii")
            transmission = bytearray(RAW_MAGIC + struct.pack("!H", len(encoded)) + encoded)
        sock = socket.create_connection((config["pinnedIPv4"], config["pinnedPort"]),
                                        timeout=config["timeoutMs"] / 1000)
        result["tcpConnected"] = True
        sock.settimeout(min(config["timeoutMs"] / 1000, 0.75))
        sock.sendall(transmission)
        result["explicitSocketWriteCount"] = 1
        if config["mode"] == "direct-tls":
            result["clientHelloSent"] = True
        transmission[:] = b"\x00" * len(transmission)
        try:
            result["receivedResponse"] = bool(sock.recv(config["maxResponseBytes"]))
        except (socket.timeout, ConnectionResetError, OSError):
            pass
        result.update({"phase": "sent", "durationMs": round((time.monotonic() - started) * 1000)})
        return result, 0
    except BaseException as error:
        code = safe_error_code(error)
        result.update({"phase": "blocked" if not result["tcpConnected"] else "send", "errorCode": code,
                       "timedOut": code == "ETIMEDOUT", "durationMs": round((time.monotonic() - started) * 1000)})
        return result, 0
    finally:
        if transmission is not None:
            transmission[:] = b"\x00" * len(transmission)
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def run_smtp(config: dict[str, Any]) -> tuple[dict[str, Any], int]:
    result = base_result(config)
    sock: socket.socket | None = None
    wrapped: ssl.SSLSocket | None = None
    secret_bytes: bytearray | None = None
    ehlo: bytearray | None = None
    started = time.monotonic()
    try:
        sock = socket.create_connection((config["pinnedIPv4"], config["pinnedPort"]),
                                        timeout=config["timeoutMs"] / 1000)
        result["tcpConnected"] = True
        sock.settimeout(config["timeoutMs"] / 1000)
        greeting = receive_smtp_reply(sock, 220, config["maxResponseBytes"])
        expected = f"220 s43-{config['greetingTag']}.{config['endpointHostname']} ESMTP SBX043".encode("ascii")
        if greeting != [expected]:
            raise ValueError("SMTP greeting tag did not match this case")
        result.update({"validGreetingReceived": True, "greetingTagMatched": True, "receivedResponse": True})
        if config["mode"] == "smtp-starttls-secret":
            proof_name, secret_bytes, mode = read_secret_proof_name(config)
            result.update({"operatorSecretFileValidated": True, "operatorSecretFileMode": mode,
                           "secretReadAfterGreeting": True})
        else:
            proof_name = public_proof_name(config)
        ehlo = bytearray(f"EHLO {proof_name}\r\n".encode("ascii"))
        if len(ehlo) > 512:
            raise ValueError("EHLO command exceeded RFC 5321 line bound")
        sock.sendall(ehlo)
        result.update({"ehloSent": True, "ehloBytes": len(ehlo), "explicitSocketWriteCount": 1})
        ehlo[:] = b"\x00" * len(ehlo)
        if secret_bytes is not None:
            secret_bytes[:] = b"\x00" * len(secret_bytes)
        capabilities = receive_smtp_reply(sock, 250, config["maxResponseBytes"])
        if not any(line[4:].upper() == b"STARTTLS" for line in capabilities):
            raise ValueError("SMTP server did not advertise STARTTLS")
        result["startTlsAdvertised"] = True
        sock.sendall(b"STARTTLS\r\n")
        result.update({"startTlsCommandSent": True, "explicitSocketWriteCount": 2})
        ready = receive_smtp_reply(sock, 220, config["maxResponseBytes"])
        if ready != [b"220 2.0.0 Ready to start TLS"]:
            raise ValueError("SMTP STARTTLS ready response was invalid")
        result["startTlsReadyReceived"] = True
        context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        wrapped = context.wrap_socket(sock, server_hostname=config["endpointHostname"])
        sock = None
        result.update({"clientHelloGenerated": True, "clientHelloSent": True, "tlsHandshakeComplete": True,
                       "peerCertificateVerified": True})
        wrapped.sendall(b"EHLO post.sbx043.invalid\r\n")
        result["explicitSocketWriteCount"] = 3
        post = receive_smtp_reply(wrapped, 250, config["maxResponseBytes"])
        if post != [b"250 post-tls-ok"]:
            raise ValueError("post-TLS EHLO response was invalid")
        result.update({"postTlsEhloComplete": True, "phase": "complete",
                       "durationMs": round((time.monotonic() - started) * 1000)})
        return result, 0
    except BaseException as error:
        code = safe_error_code(error)
        result.update({"phase": "blocked" if not result["tcpConnected"] else "smtp-or-tls", "errorCode": code,
                       "timedOut": code == "ETIMEDOUT", "durationMs": round((time.monotonic() - started) * 1000)})
        return result, 0
    finally:
        for value in (ehlo, secret_bytes):
            if value is not None:
                value[:] = b"\x00" * len(value)
        for candidate in (wrapped, sock):
            if candidate is not None:
                try:
                    candidate.close()
                except OSError:
                    pass


def plan(config: dict[str, Any]) -> dict[str, Any]:
    result = base_result(config)
    result.update({
        "phase": "plan",
        "maximumNetworkAttempts": 1,
        "maximumSmtpLineBytes": 512,
        "strictCertificateVerification": config["mode"] in ("https-control", "smtp-starttls-public", "smtp-starttls-secret"),
        "secretPathFixed": config["mode"] == "smtp-starttls-secret",
        "secretReadAfterValidGreeting": config["mode"] == "smtp-starttls-secret",
    })
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
            result, exit_code = run_smtp(config)
    except BaseException as error:
        result = {"ok": False, "phase": "configuration", "errorCode": error.__class__.__name__[:64],
                  "rawConfigurationRetained": False, "rawEhloRetained": False,
                  "rawOperatorSecretRetained": False}
        exit_code = 20
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
