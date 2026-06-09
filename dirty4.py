"""IEEE 1284.4 (D4) transport for Epson printer communication.

Key protocol facts
------------------
- Channel 0 is the control channel (always open).
- Data channels are opened by name via GetSocketID + OpenChannel.
- Credits gate how many packets you may send on a channel; the peer
  grants you more credits by including a non-zero credit field in its
  own packets, or via explicit Credit / CreditRequest commands.
- Every D4 packet has a 6-byte header: psid, ssid, length (big-endian
  uint16), credit, control.
"""

import binascii
import logging
import os
import select
import struct
import time
from collections import namedtuple
from dataclasses import dataclass, field
from typing import List

log = logging.getLogger('dirty4')

# Seconds to wait for data before raising TimeoutError.
READ_TIMEOUT = 60

D4Packet = namedtuple(
    'D4Packet',
    ['psid', 'ssid', 'payload', 'credit', 'oob', 'eom'],
    defaults=[None, b'', 1, False, False],
)

commands = {
    'Init':          0,
    'OpenChannel':   1,
    'CloseChannel':  2,
    'Credit':        3,
    'CreditRequest': 4,
    'Exit':          8,
    'GetSocketID':   9,
}

errors = {
    0x80: 'Malformed packet',
    0x81: 'No credit',
    0x82: 'Reply without command',
    0x83: 'Packet too big',
    0x84: 'Channel not open',
    0x85: 'Unknown result',
    0x86: 'Credit overflow',
    0x87: 'Bad command/reply',
}


@dataclass
class DirtyChannel:
    sid: int
    mtu: int
    credits: int = 0
    rx_queue: List[D4Packet] = field(default_factory=list)


class DirtyChannelContext:
    """Context manager that opens a named D4 channel on entry and closes it on exit.

    The sid attribute is only set once GetSocketID succeeds, so __exit__
    will safely skip CloseChannel if __enter__ raised before that point.
    """

    def __init__(self, d4, name: str):
        self.d4 = d4
        self.name = name
        self.sid = None
        self.chan = None

    def __enter__(self):
        self.sid = self.d4.GetSocketID(self.name)
        self.chan = self.d4.OpenChannel(self.sid)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.sid is not None:
            try:
                self.d4.CloseChannel(self.sid)
            except Exception as e:
                log.warning('Failed to close channel %d (%s): %s', self.sid, self.name, e)
        return False  # do not suppress caller exceptions

    @property
    def credits(self) -> int:
        return self.chan.credits

    def ensure_credit(self):
        """Block until this channel has at least one outbound credit."""
        if self.credits < 1:
            while self.d4.CreditRequest(self.sid) < 1:
                time.sleep(0.1)

    def write(self, data, progress=None):
        """Write data to the channel, splitting on MTU boundaries.

        Uses a memoryview to avoid O(n²) byte-string copying for large
        payloads (e.g. a several-MB firmware blob).
        """
        buf = memoryview(data if isinstance(data, (bytes, bytearray)) else bytes(data))
        n = len(buf)
        offset = 0
        while offset < n:
            chunk_size = min(n - offset, self.chan.mtu - 6)
            payload = bytes(buf[offset:offset + chunk_size])
            eom = (offset + chunk_size >= n)
            offset += chunk_size
            self.ensure_credit()
            self.d4.write_packet(self.sid, eom=eom, payload=payload)
            if progress:
                progress(chunk_size)

    def read(self) -> D4Packet:
        self.d4.Credit(self.sid, 1)
        return self.d4.read_packet(self.sid)

    def cmd2(self, name: str, payload, binary: bool = False):
        """Send a 2-char EJL command and return the decoded response."""
        if len(name) != 2:
            raise ValueError(f'Command name must be exactly 2 chars, got {name!r}')
        if isinstance(payload, int):
            payload = bytearray([payload])
        msg = name.encode('ascii') + struct.pack('<H', len(payload)) + bytes(payload)
        self.write(msg)
        result = self.read().payload
        return result if binary else result.decode('ascii')


class Dirty4:
    """IEEE 1284.4 transport layer."""

    def __init__(self, port):
        self.port = port
        self.buffer = bytearray()          # mutable; avoids O(n²) bytes += bytes
        self.channels = {0: DirtyChannel(sid=0, mtu=64)}

        self._drain()                      # discard any stale/periodic status data
        self._write(b'\x00\x00\x00\x1b\x01@EJL 1284.4\n@EJL\n@EJL\n')
        self._read(8)                      # consume D4 mode acknowledgement
        self.Init()

    # ------------------------------------------------------------------
    # Low-level I/O
    # ------------------------------------------------------------------

    def _drain(self):
        """Discard buffered device data without blocking.

        The original os.read(port, 131072) call could block indefinitely
        if there is nothing queued; select() lets us stop after 200 ms of
        silence instead.
        """
        while True:
            ready, _, _ = select.select([self.port], [], [], 0.2)
            if not ready:
                break
            chunk = os.read(self.port, 4096)
            if not chunk:
                break
            log.debug('drain: discarded %d bytes', len(chunk))

    def _write(self, data):
        """Write all of data, retrying on short writes.

        Uses a memoryview offset to avoid copying the remainder of a large
        buffer on every partial-write retry.
        """
        view = memoryview(data if isinstance(data, (bytes, bytearray)) else bytes(data))
        offset = 0
        while offset < len(view):
            written = os.write(self.port, view[offset:])
            if written == 0:
                time.sleep(0.05)
            else:
                offset += written

    def _read(self, length: int, timeout: float = READ_TIMEOUT) -> bytes:
        """Read exactly length bytes, raising TimeoutError if we wait too long.

        The original implementation busy-looped on os.read returning b'',
        which would spin forever if the device closed mid-read.  select()
        gives us a proper deadline.
        """
        deadline = time.monotonic() + timeout
        while len(self.buffer) < length:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(
                    f'Timed out after {timeout}s waiting for data '
                    f'(want {length} bytes, have {len(self.buffer)})'
                )
            ready, _, _ = select.select([self.port], [], [], min(remaining, 1.0))
            if ready:
                chunk = os.read(self.port, 4096)
                if chunk:
                    self.buffer.extend(chunk)
        result = bytes(self.buffer[:length])
        del self.buffer[:length]
        return result

    # ------------------------------------------------------------------
    # Packet layer
    # ------------------------------------------------------------------

    def write_packet(self, psid: int, **kwargs):
        packet = D4Packet(psid, **kwargs)
        ssid = packet.ssid if packet.ssid is not None else packet.psid
        control = (0x02 if packet.eom else 0x00) | (0x01 if packet.oob else 0x00)
        length = 6 + len(packet.payload)
        header = struct.pack('>BBHBB', packet.psid, ssid, length, packet.credit, control)
        raw = header + packet.payload
        log.debug('> %s', ' '.join('%02x' % b for b in raw[:0x40]))
        self._write(raw)
        ch = self.channels.get(packet.psid)
        if ch and ch.credits:
            ch.credits -= 1

    def read_next_packet(self):
        header_raw = self._read(6)
        psid, ssid, length, credit, control = struct.unpack('>BBHBB', header_raw)
        payload = self._read(length - 6)
        log.debug('< %s', ' '.join('%02x' % b for b in (header_raw + payload)[:0x40]))

        ch = self.channels.get(psid)
        if ch is None:
            log.warning('Packet for unknown socket ID %d; discarding', psid)
            return

        ch.credits += credit
        ch.rx_queue.append(
            D4Packet(psid, ssid, payload, credit, bool(control & 1), bool(control & 2))
        )

    def read_packet(self, sid: int) -> D4Packet:
        ch = self.channels[sid]
        while not ch.rx_queue:
            self.read_next_packet()
        return ch.rx_queue.pop(0)

    # ------------------------------------------------------------------
    # Command layer
    # ------------------------------------------------------------------

    def command(self, name: str, payload: bytes = b'') -> bytes:
        if name not in ('Init', 'Exit') and not self.channels[0].credits:
            raise RuntimeError(
                f"No credits on control channel; cannot send '{name}'. "
                "Has the D4 session been properly initialised?"
            )

        log.debug('command: %s %s', name, binascii.hexlify(payload))
        cmd_byte = commands[name]
        self.write_packet(0, payload=bytearray([cmd_byte]) + payload)
        resp = self.read_packet(0)

        if resp.psid != 0:
            raise RuntimeError(
                f"Expected response on channel 0, got channel {resp.psid} for '{name}'"
            )

        resp_bytes = bytearray(resp.payload)

        if resp_bytes[0] == 0x7f:                   # error response
            code = resp_bytes[3] if len(resp_bytes) > 3 else 0
            msg = errors.get(code, f'unknown code 0x{code:02x}')
            raise RuntimeError(f"D4 error for '{name}': {msg}")

        expected = cmd_byte | 0x80
        if resp_bytes[0] != expected:
            raise RuntimeError(
                f"Unexpected response byte 0x{resp_bytes[0]:02x} for '{name}' "
                f"(expected 0x{expected:02x})"
            )

        return resp.payload[2:]

    # ------------------------------------------------------------------
    # D4 commands
    # ------------------------------------------------------------------

    def Init(self):
        resp = self.command('Init', b'\x10')
        if resp != b'\x10':
            raise RuntimeError(f'Unexpected Init response: {resp!r}')

    def Exit(self):
        self.command('Exit')

    def GetSocketID(self, name: str) -> int:
        resp = self.command('GetSocketID', name.encode('ascii'))
        return int(resp[0])

    def OpenChannel(self, sid: int) -> DirtyChannel:
        req = struct.pack('>BBHHHH', sid, sid, 0xffff, 0xffff, 0xffff, 0xffff)
        resp = self.command('OpenChannel', req)
        psid, ssid, mtu, max_credit, credit = struct.unpack('>BBHHH', resp)
        self.channels[sid] = DirtyChannel(sid=psid, mtu=mtu, credits=credit)
        return self.channels[sid]

    def CloseChannel(self, sid: int):
        req = struct.pack('>BB', sid, sid)
        self.command('CloseChannel', req)
        self.channels.pop(sid, None)

    def Credit(self, sid: int, amount: int):
        req = struct.pack('>BBH', sid, sid, amount)
        self.command('Credit', req)

    def CreditRequest(self, sid: int, amount: int = 0x100) -> int:
        req = struct.pack('>BBH', sid, sid, amount)
        resp = self.command('CreditRequest', req)
        _, _, granted = struct.unpack('>BBH', resp)
        self.channels[sid].credits += granted
        return granted

    def channel(self, name: str) -> DirtyChannelContext:
        return DirtyChannelContext(self, name)
