"""A small HTTP/3 server (aioquic) for the tests of the QUIC side of curl and of the ngtcp2 helper.

  python3 -m venv ~/.cache/quic-test/venv && ~/.cache/quic-test/venv/bin/pip install aioquic
  RETRY=1 KEY_UPDATES=1 CHUNKS=24 ~/.cache/quic-test/venv/bin/python downstream/tests/aioquic-server.py
  curl --http3-only --cacert librustls/testdata/minica.pem -o /dev/null -w '%{size_download}\n' https://localhost:4433/

It serves the certificate of librustls/testdata/localhost (made by the CA librustls/testdata/minica.pem) on UDP
4433. RETRY=1 makes it answer the first Initial with a Retry (and print RETRY SENT); KEY_UPDATES=1 makes it update
its keys between the chunks of a large response (and print SERVER KEY UPDATE); CHUNKS is the number of 256 KiB
chunks of the body (the byte i of chunk n is n % 251, so the body can be checked)."""
import asyncio, logging, os, sys
from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ProtocolNegotiated

CHUNK = 256 * 1024
CHUNKS = int(os.environ.get("CHUNKS", "16"))
RETRY = os.environ.get("RETRY") == "1"
KEY_UPDATES = os.environ.get("KEY_UPDATES") == "1"
DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "librustls", "testdata", "localhost")


class Proto(QuicConnectionProtocol):
    http = None

    def quic_event_received(self, event):
        if isinstance(event, ProtocolNegotiated):
            self.http = H3Connection(self._quic)
        if self.http is not None:
            for ev in self.http.handle_event(event):
                if isinstance(ev, HeadersReceived):
                    asyncio.ensure_future(self.respond(ev.stream_id))

    async def respond(self, sid):
        print("request on stream", sid, flush=True)
        self.http.send_headers(sid, [(b":status", b"200"), (b"content-length", str(CHUNK * CHUNKS).encode())])
        for i in range(CHUNKS):
            self.http.send_data(sid, bytes([i % 251]) * CHUNK, end_stream=(i == CHUNKS - 1))
            self.transmit()
            if KEY_UPDATES and i % 4 == 3 and i != CHUNKS - 1:
                await asyncio.sleep(0.6)
                self._quic.request_key_update()
                self.transmit()
                print("key update requested after chunk", i, flush=True)
            else:
                await asyncio.sleep(0.02)


import aioquic.asyncio.server as _srv
_orig_retry = _srv.encode_quic_retry


def _retry(*args, **kwargs):
    print("RETRY SENT", flush=True)
    return _orig_retry(*args, **kwargs)


_srv.encode_quic_retry = _retry


from aioquic.quic.crypto import CryptoPair
_orig_update = CryptoPair._update_key


def _update(self, trigger):
    _orig_update(self, trigger)
    print("SERVER KEY UPDATE (%s): send phase %d, recv phase %d" % (trigger, self.send.key_phase, self.recv.key_phase), flush=True)


CryptoPair._update_key = _update


async def main():
    logging.basicConfig(level=logging.INFO)
    config = QuicConfiguration(alpn_protocols=H3_ALPN, is_client=False)
    config.load_cert_chain(DIR + "/cert.pem", DIR + "/key.pem")
    await serve("::", 4433, configuration=config, create_protocol=Proto, retry=RETRY)
    print("serving, retry=%s key_updates=%s" % (RETRY, KEY_UPDATES), flush=True)
    await asyncio.Future()


asyncio.run(main())
