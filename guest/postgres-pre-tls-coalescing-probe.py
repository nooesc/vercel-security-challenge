#!/usr/bin/env python3
"""One-shot PostgreSQL SSLRequest/coalescing probe for SBX-036.

The coalesced modes intentionally append a bounded discriminator to a valid
PostgreSQL SSLRequest. That suffix is not claimed to be a valid PostgreSQL TLS
flight. The independently controlled listener decides whether the suffix
arrived before it sent the one-byte PostgreSQL SSL response.
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
import struct
import sys
import time
from typing import Any


TEST_ID = "SBX-036-POC"
SCOPE_CONFIRMATION = (
    "I_CONTROL_DISTINCT_HTTPS_ALLOW_AND_DIRECT_POSTGRES_DENIED_ENDPOINTS_AND_AUTHORIZE_BOUNDED_PRETLS_TESTING"
)
SSL_REQUEST_CODE = 80877103
SSL_REQUEST = struct.pack("!II", 8, SSL_REQUEST_CODE)
FRAME_MAGIC = b"SBX036P1"
SECRET_PATH = "/tmp/sbx-036/operator-secret"
MAX_FRAME_BYTES = 256
MAX_RESPONSE_BYTES = 2048
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
CASE_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
DNS_NAME = re.compile(
    r"^(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
PUBLIC_CANARY = re.compile(r"^pub_[A-Za-z0-9_-]{24}$")
SECRET = re.compile(r"^opsec_[A-Za-z0-9_-]{43}$")
PUBLIC_OPERATION = re.compile(r"^pgp_[A-Za-z0-9_-]{43}$")
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
        "expectedOperationId",
        "timeoutMs",
        "maxResponseBytes",
    )
)


class ConfigurationError(ValueError):
    pass


def _record(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConfigurationError(f"{field} must be an object")
    return value


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
    config = _record(value, "configuration")
    unknown = sorted(set(config) - ALLOWED_KEYS)
    if unknown:
        raise ConfigurationError(f"configuration field {json.dumps(unknown[0])} is not allowed")
    if config.get("scopeConfirmation") != SCOPE_CONFIRMATION:
        raise ConfigurationError("scopeConfirmation is not exact")
    if config.get("testId") != TEST_ID:
        raise ConfigurationError("testId is not exact")
    mode = config.get("mode")
    if mode not in ("postgres-tls", "coalesced-tls", "coalesced-public", "coalesced-secret", "raw-public"):
        raise ConfigurationError("mode is not one fixed SBX-036 mode")
    run_id = config.get("runId")
    case_id = config.get("caseId")
    role = config.get("endpointRole")
    if not isinstance(run_id, str) or UUID.fullmatch(run_id) is None:
        raise ConfigurationError("runId must be a canonical random UUID")
    if not isinstance(case_id, str) or CASE_ID.fullmatch(case_id) is None:
        raise ConfigurationError("caseId must be a bounded lowercase identifier")
    if role not in ("allowed", "denied"):
        raise ConfigurationError("endpointRole must be allowed or denied")
    if mode != "postgres-tls" and role != "denied":
        raise ConfigurationError("raw/coalesced modes are fixed to the distinct denied listener")
    public_canary = config.get("publicCanary")
    expected_operation_id = config.get("expectedOperationId")
    if mode == "coalesced-secret":
        if "publicCanary" in config or "expectedOperationId" in config:
            raise ConfigurationError("the secret mode may only read the fixed guest secret file")
    else:
        if not isinstance(public_canary, str) or PUBLIC_CANARY.fullmatch(public_canary) is None:
            raise ConfigurationError("public modes require one bounded publicCanary")
        if mode in ("postgres-tls", "coalesced-tls"):
            if not isinstance(expected_operation_id, str) or PUBLIC_OPERATION.fullmatch(expected_operation_id) is None:
                raise ConfigurationError("postgres-tls requires one expected public operation ID")
        elif "expectedOperationId" in config:
            raise ConfigurationError("raw/coalesced public modes use only independent receiver proof")
    return {
        "mode": mode,
        "runId": run_id,
        "testId": TEST_ID,
        "caseId": case_id,
        "endpointRole": role,
        "endpointHostname": _canonical_hostname(config.get("endpointHostname")),
        "pinnedIPv4": _public_ipv4(config.get("pinnedIPv4")),
        "pinnedPort": _bounded_int(config.get("pinnedPort"), "pinnedPort", 1, 65535, 5432),
        **({"publicCanary": public_canary} if mode != "coalesced-secret" else {}),
        **({"expectedOperationId": expected_operation_id} if mode in ("postgres-tls", "coalesced-tls") else {}),
        "timeoutMs": _bounded_int(config.get("timeoutMs"), "timeoutMs", 250, 8000, 3000),
        "maxResponseBytes": _bounded_int(
            config.get("maxResponseBytes"), "maxResponseBytes", 256, MAX_RESPONSE_BYTES, 1024
        ),
    }


def encode_pre_tls_frame(kind: str, run_id: str, case_id: str, payload: str) -> bytes:
    if kind not in ("public", "secret"):
        raise ValueError("invalid discriminator kind")
    run_bytes = run_id.encode("ascii")
    case_bytes = case_id.encode("ascii")
    payload_bytes = bytearray(payload.encode("ascii"))
    try:
        if not 1 <= len(run_bytes) <= 64 or not 1 <= len(case_bytes) <= 63 or not 1 <= len(payload_bytes) <= 96:
            raise ValueError("pre-TLS frame field length is invalid")
        frame = b"".join(
            (
                FRAME_MAGIC,
                b"P" if kind == "public" else b"S",
                bytes((len(run_bytes), len(case_bytes))),
                struct.pack("!H", len(payload_bytes)),
                run_bytes,
                case_bytes,
                payload_bytes,
            )
        )
        if len(frame) > MAX_FRAME_BYTES:
            raise ValueError("pre-TLS frame exceeded its bound")
        return frame
    finally:
        for index in range(len(payload_bytes)):
            payload_bytes[index] = 0


def startup_packet(run_id: str, case_id: str, public_canary: str) -> bytes:
    application_name = f"sbx036|{run_id}|{case_id}|{public_canary}"
    parameters = b"".join(
        (
            b"user\x00sbx036\x00",
            b"database\x00sbx036\x00",
            b"application_name\x00",
            application_name.encode("ascii"),
            b"\x00\x00",
        )
    )
    packet = struct.pack("!II", 8 + len(parameters), 196608) + parameters
    if len(packet) > 512:
        raise ValueError("startup packet exceeded its bound")
    return packet


def parse_error_operation(data: bytes) -> str | None:
    if len(data) < 6 or data[0:1] != b"E":
        return None
    length = struct.unpack("!I", data[1:5])[0]
    if length < 5 or length + 1 > len(data):
        return None
    fields = data[5 : 1 + length]
    for field in fields.split(b"\x00"):
        if len(field) > 1 and field[0:1] == b"M":
            message = field[1:].decode("ascii", "strict")
            if message.startswith("sbx036:"):
                operation_id = message[7:]
                return operation_id if PUBLIC_OPERATION.fullmatch(operation_id) else None
    return None


def base_result(config: dict[str, Any]) -> dict[str, Any]:
    return {
        "mode": config["mode"],
        "runId": config["runId"],
        "testId": TEST_ID,
        "caseId": config["caseId"],
        "endpointRole": config["endpointRole"],
        "endpointHostname": config["endpointHostname"],
        "pinnedIPv4": config["pinnedIPv4"],
        "pinnedPort": config["pinnedPort"],
        "attemptCount": 1,
        "retryCount": 0,
        "timeout": False,
        "tcpConnected": False,
        "sslRequestExact": config["mode"] != "raw-public" and SSL_REQUEST.hex() == "0000000804d2162f",
        "sslRequestLength": 0 if config["mode"] == "raw-public" else len(SSL_REQUEST),
        "sslRequestCode": 0 if config["mode"] == "raw-public" else SSL_REQUEST_CODE,
        "sslRequestHex": "" if config["mode"] == "raw-public" else SSL_REQUEST.hex(),
        "responseStarted": False,
        "tlsEstablished": False,
        "certificateVerified": False,
        "hostnameVerified": False,
        "coalescedSingleWrite": config["mode"].startswith("coalesced-"),
        "explicitSocketWriteCount": 0,
        "bytesAfterSslRequest": 0,
        "payloadRetained": False,
        "payloadDigestRetained": False,
        "rawConfigurationRetained": False,
    }


def plan(config: dict[str, Any]) -> dict[str, Any]:
    result = base_result(config)
    result.update(
        {
            "ok": True,
            "phase": "plan",
            "strictCertificateVerification": config["mode"] in ("postgres-tls", "coalesced-tls"),
            "hostnameVerificationRequired": config["mode"] in ("postgres-tls", "coalesced-tls"),
            "secretPathFixed": config["mode"] == "coalesced-secret",
            "maximumNetworkAttempts": 1,
            "maximumFrameBytes": MAX_FRAME_BYTES,
        }
    )
    if config["mode"] in ("coalesced-public", "raw-public"):
        result["discriminatorKind"] = "public"
    elif config["mode"] == "coalesced-secret":
        result["discriminatorKind"] = "secret"
    return result


def safe_error_code(error: BaseException) -> str:
    if isinstance(error, socket.timeout):
        return "VSC_TIMEOUT"
    if isinstance(error, ssl.SSLError):
        return "PG_TLS_REJECTED"
    if isinstance(error, OSError) and error.errno is not None:
        names = {
            32: "EPIPE",
            54: "ECONNRESET",
            65: "EHOSTUNREACH",
            104: "ECONNRESET",
            113: "EHOSTUNREACH",
        }
        return names.get(error.errno, f"ERRNO_{error.errno}")
    return error.__class__.__name__[:64]


def run_coalesced(config: dict[str, Any]) -> tuple[dict[str, Any], int]:
    result = base_result(config)
    secret_bytes: bytearray | None = None
    payload = ""
    sock: socket.socket | None = None
    sent = False
    started = time.monotonic()
    try:
        if config["mode"] == "coalesced-secret":
            file_stat = os.stat(SECRET_PATH, follow_symlinks=False)
            if not stat.S_ISREG(file_stat.st_mode) or stat.S_IMODE(file_stat.st_mode) != 0o600:
                raise ValueError("operator secret file must be regular mode 0600")
            raw = open(SECRET_PATH, "rb", buffering=0).read(128)
            secret_bytes = bytearray(raw)
            if len(secret_bytes) > 96:
                raise ValueError("operator secret file exceeded its bound")
            payload = secret_bytes.decode("ascii", "strict")
            if SECRET.fullmatch(payload) is None:
                raise ValueError("operator secret has the wrong shape")
            kind = "secret"
        else:
            payload = config["publicCanary"]
            kind = "public"
        frame = encode_pre_tls_frame(kind, config["runId"], config["caseId"], payload)
        transmission = bytearray(frame if config["mode"] == "raw-public" else SSL_REQUEST + frame)
        result["bytesAfterSslRequest"] = len(frame)
        result["discriminatorKind"] = kind
        sock = socket.create_connection(
            (config["pinnedIPv4"], config["pinnedPort"]),
            timeout=config["timeoutMs"] / 1000,
        )
        result["tcpConnected"] = True
        sock.settimeout(min(config["timeoutMs"] / 1000, 1.0))
        sock.sendall(transmission)
        result["explicitSocketWriteCount"] = 1
        sent = True
        for index in range(len(transmission)):
            transmission[index] = 0
        try:
            response = sock.recv(1)
            if response:
                result["responseStarted"] = True
                result["serverSslResponse"] = response.decode("ascii", "replace")
        except socket.timeout:
            pass
        result.update({"ok": True, "phase": "sent", "durationMs": round((time.monotonic() - started) * 1000)})
        return result, 0
    except BaseException as error:
        result.update(
            {
                "ok": sent,
                "phase": "sent" if sent else "connect",
                "errorCode": safe_error_code(error),
                "timeout": isinstance(error, socket.timeout) and not sent,
                "durationMs": round((time.monotonic() - started) * 1000),
            }
        )
        return result, 0 if sent else 10
    finally:
        payload = ""
        if secret_bytes is not None:
            for index in range(len(secret_bytes)):
                secret_bytes[index] = 0
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def run_postgres_tls(config: dict[str, Any]) -> tuple[dict[str, Any], int]:
    result = base_result(config)
    raw: socket.socket | None = None
    wrapped: ssl.SSLSocket | None = None
    started = time.monotonic()
    try:
        raw = socket.create_connection(
            (config["pinnedIPv4"], config["pinnedPort"]),
            timeout=config["timeoutMs"] / 1000,
        )
        result["tcpConnected"] = True
        raw.settimeout(config["timeoutMs"] / 1000)
        raw.sendall(SSL_REQUEST)
        result["explicitSocketWriteCount"] = 1
        response = raw.recv(1)
        if response:
            result["responseStarted"] = True
            result["serverSslResponse"] = response.decode("ascii", "replace")
        if response != b"S":
            raise ssl.SSLError("PostgreSQL server did not accept TLS")
        context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        wrapped = context.wrap_socket(raw, server_hostname=config["endpointHostname"])
        raw = None
        result["tlsEstablished"] = True
        result["certificateVerified"] = True
        result["hostnameVerified"] = True
        result["tlsVersion"] = wrapped.version()
        wrapped.settimeout(config["timeoutMs"] / 1000)
        packet = startup_packet(config["runId"], config["caseId"], config["publicCanary"])
        wrapped.sendall(packet)
        result["explicitSocketWriteCount"] = 2
        response_bytes = bytearray()
        while len(response_bytes) < config["maxResponseBytes"]:
            chunk = wrapped.recv(min(512, config["maxResponseBytes"] - len(response_bytes)))
            if not chunk:
                break
            response_bytes.extend(chunk)
            operation_id = parse_error_operation(bytes(response_bytes))
            if operation_id is not None:
                break
        operation_id = parse_error_operation(bytes(response_bytes))
        response_bytes[:] = b"\x00" * len(response_bytes)
        if operation_id != config["expectedOperationId"]:
            raise ValueError("receiver operation ID was absent or not exact")
        result.update(
            {
                "ok": True,
                "phase": "complete",
                "operationId": operation_id,
                "durationMs": round((time.monotonic() - started) * 1000),
            }
        )
        return result, 0
    except BaseException as error:
        code = safe_error_code(error)
        result.update(
            {
                "ok": False,
                "phase": "handshake" if result["responseStarted"] else "connect",
                "errorCode": code,
                "timeout": code == "VSC_TIMEOUT",
                "durationMs": round((time.monotonic() - started) * 1000),
            }
        )
        return result, 10
    finally:
        for sock in (wrapped, raw):
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass


def _drain_memory_bio(outgoing: ssl.MemoryBIO, sock: socket.socket, result: dict[str, Any]) -> None:
    while outgoing.pending:
        data = outgoing.read()
        if not data:
            break
        sock.sendall(data)
        result["explicitSocketWriteCount"] += 1


def run_coalesced_tls(config: dict[str, Any]) -> tuple[dict[str, Any], int]:
    """Send SSLRequest and one complete ClientHello in the first wire write.

    PostgreSQL documents this early-handshake pattern as a latency optimization,
    although a client then cannot recover from a negative SSL response. The same
    MemoryBIO handshake is continued after the receiver's one-byte `S`.
    """

    result = base_result(config)
    raw: socket.socket | None = None
    started = time.monotonic()
    incoming = ssl.MemoryBIO()
    outgoing = ssl.MemoryBIO()
    try:
        context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        tls_object = context.wrap_bio(
            incoming,
            outgoing,
            server_side=False,
            server_hostname=config["endpointHostname"],
        )
        try:
            tls_object.do_handshake()
        except ssl.SSLWantReadError:
            pass
        first_flight = bytearray()
        while outgoing.pending:
            first_flight.extend(outgoing.read())
        if (
            len(first_flight) < 6
            or len(first_flight) > 16_384
            or first_flight[0] != 0x16
            or first_flight[1] != 0x03
        ):
            raise ValueError("MemoryBIO did not produce one bounded TLS ClientHello flight")
        result["bytesAfterSslRequest"] = len(first_flight)
        result["initialClientHelloSha256"] = hashlib.sha256(first_flight).hexdigest()
        result["initialClientHelloRetained"] = False
        transmission = bytearray(SSL_REQUEST)
        transmission.extend(first_flight)
        first_flight[:] = b"\x00" * len(first_flight)
        raw = socket.create_connection(
            (config["pinnedIPv4"], config["pinnedPort"]),
            timeout=config["timeoutMs"] / 1000,
        )
        result["tcpConnected"] = True
        raw.settimeout(config["timeoutMs"] / 1000)
        raw.sendall(transmission)
        result["explicitSocketWriteCount"] = 1
        transmission[:] = b"\x00" * len(transmission)

        first_response = raw.recv(16_384)
        if not first_response:
            raise ConnectionResetError("receiver closed before PostgreSQL SSL response")
        result["responseStarted"] = True
        result["serverSslResponse"] = first_response[0:1].decode("ascii", "replace")
        if first_response[0:1] != b"S":
            raise ssl.SSLError("PostgreSQL server did not accept TLS")
        if len(first_response) > 1:
            incoming.write(first_response[1:])

        while True:
            try:
                tls_object.do_handshake()
                break
            except ssl.SSLWantWriteError:
                _drain_memory_bio(outgoing, raw, result)
            except ssl.SSLWantReadError:
                _drain_memory_bio(outgoing, raw, result)
                server_bytes = raw.recv(16_384)
                if not server_bytes:
                    raise ConnectionResetError("receiver closed during coalesced TLS handshake")
                incoming.write(server_bytes)
        _drain_memory_bio(outgoing, raw, result)
        result["tlsEstablished"] = True
        result["certificateVerified"] = True
        result["hostnameVerified"] = True
        result["tlsVersion"] = tls_object.version()

        application = startup_packet(config["runId"], config["caseId"], config["publicCanary"])
        while application:
            try:
                written = tls_object.write(application)
                application = application[written:]
            except ssl.SSLWantWriteError:
                _drain_memory_bio(outgoing, raw, result)
        _drain_memory_bio(outgoing, raw, result)

        plaintext = bytearray()
        while len(plaintext) < config["maxResponseBytes"]:
            try:
                chunk = tls_object.read(config["maxResponseBytes"] - len(plaintext))
                if not chunk:
                    break
                plaintext.extend(chunk)
                operation_id = parse_error_operation(bytes(plaintext))
                if operation_id is not None:
                    break
            except ssl.SSLWantWriteError:
                _drain_memory_bio(outgoing, raw, result)
            except ssl.SSLWantReadError:
                _drain_memory_bio(outgoing, raw, result)
                server_bytes = raw.recv(16_384)
                if not server_bytes:
                    break
                incoming.write(server_bytes)
        operation_id = parse_error_operation(bytes(plaintext))
        plaintext[:] = b"\x00" * len(plaintext)
        if operation_id != config["expectedOperationId"]:
            raise ValueError("receiver operation ID was absent or not exact")
        result.update(
            {
                "ok": True,
                "phase": "complete",
                "operationId": operation_id,
                "durationMs": round((time.monotonic() - started) * 1000),
            }
        )
        return result, 0
    except BaseException as error:
        code = safe_error_code(error)
        result.update(
            {
                "ok": False,
                "phase": "handshake" if result["responseStarted"] else "connect",
                "errorCode": code,
                "timeout": code == "VSC_TIMEOUT",
                "durationMs": round((time.monotonic() - started) * 1000),
            }
        )
        return result, 10
    finally:
        if raw is not None:
            try:
                raw.close()
            except OSError:
                pass


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


def main() -> int:
    if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] != "--plan"):
        print(json.dumps({"ok": False, "phase": "configuration", "errorCode": "ARGUMENTS"}))
        return 20
    try:
        config = validate_configuration(decode_argument(sys.argv[1]))
        if len(sys.argv) == 3:
            result, exit_code = plan(config), 0
        elif config["mode"] == "postgres-tls":
            result, exit_code = run_postgres_tls(config)
        elif config["mode"] == "coalesced-tls":
            result, exit_code = run_coalesced_tls(config)
        else:
            result, exit_code = run_coalesced(config)
    except BaseException as error:
        result = {
            "ok": False,
            "phase": "configuration",
            "errorCode": error.__class__.__name__[:64],
            "payloadRetained": False,
            "payloadDigestRetained": False,
            "rawConfigurationRetained": False,
        }
        exit_code = 20
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
