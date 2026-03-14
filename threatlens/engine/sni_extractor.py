"""
ThreatLens – SNI Extractor
Parses raw TLS ClientHello bytes to extract the Server Name Indication (SNI).
Even HTTPS traffic leaks the target domain in the first unencrypted handshake packet.
"""

from typing import Optional
import struct


def extract_sni(payload: bytes) -> Optional[str]:
    """
    Parse a TLS ClientHello and return the SNI hostname, or None if not found.

    TLS Record structure:
      [0]    Content Type  = 0x16 (Handshake)
      [1-2]  Version
      [3-4]  Record Length
      [5]    Handshake Type = 0x01 (ClientHello)
      [6-8]  Handshake Length (3 bytes)
      [9-10] Client Version
      [11-42] Random (32 bytes)
      [43]   Session ID Length (N)
      [44..44+N] Session ID
      ... Cipher Suites, Compression, Extensions ...
    """
    if not payload or len(payload) < 43:
        return None

    # Must be TLS Handshake record
    if payload[0] != 0x16:
        return None

    # Must be ClientHello
    if len(payload) < 6 or payload[5] != 0x01:
        return None

    try:
        offset = 43  # skip to session ID length

        # Skip Session ID
        if offset >= len(payload):
            return None
        session_len = payload[offset]
        offset += 1 + session_len

        # Skip Cipher Suites
        if offset + 2 > len(payload):
            return None
        cipher_len = struct.unpack_from("!H", payload, offset)[0]
        offset += 2 + cipher_len

        # Skip Compression Methods
        if offset >= len(payload):
            return None
        comp_len = payload[offset]
        offset += 1 + comp_len

        # Extensions length
        if offset + 2 > len(payload):
            return None
        ext_total_len = struct.unpack_from("!H", payload, offset)[0]
        offset += 2
        ext_end = offset + ext_total_len

        # Walk extensions looking for SNI (type 0x0000)
        while offset + 4 <= ext_end and offset + 4 <= len(payload):
            ext_type = struct.unpack_from("!H", payload, offset)[0]
            ext_len  = struct.unpack_from("!H", payload, offset + 2)[0]
            offset  += 4

            if ext_type == 0x0000:  # SNI extension
                # SNI list length (2 bytes) + SNI type (1 byte) + SNI length (2 bytes)
                if offset + 5 > len(payload):
                    return None
                # sni_list_len = struct.unpack_from("!H", payload, offset)[0]
                # sni_type     = payload[offset + 2]  # 0x00 = hostname
                sni_name_len = struct.unpack_from("!H", payload, offset + 3)[0]
                name_start   = offset + 5
                if name_start + sni_name_len > len(payload):
                    return None
                return payload[name_start: name_start + sni_name_len].decode("ascii", errors="ignore")

            offset += ext_len

    except (struct.error, IndexError):
        pass

    return None


def extract_http_host(payload: bytes) -> Optional[str]:
    """Extract the HTTP Host header value from a plaintext HTTP request."""
    try:
        text = payload.decode("utf-8", errors="ignore")
        for line in text.split("\r\n"):
            if line.lower().startswith("host:"):
                host = line[5:].strip()
                # Strip port if present
                if ":" in host:
                    host = host.split(":")[0]
                return host
    except Exception:
        pass
    return None
