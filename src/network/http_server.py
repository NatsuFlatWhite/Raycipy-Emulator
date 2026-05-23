import asyncio
import logging

logger = logging.getLogger("HttpServer")


def build_serverlist(channels: list[dict]) -> bytes:
    lines = [
        "<?xml version='1.0' encoding='UTF-16'?>",
        "<server>",
        '\t<server name="레이시티">',
    ]
    for ch in channels:
        name = ch["name"]
        ip = ch["ip"]
        port = ch["port"]
        lines.append(f'\t\t<channel name="{name}" ip="{ip}" port="{port}">')
        lines.append(f'\t\t\t<ip>{ip}</ip>')
        lines.append(f'\t\t\t<port>{port}</port>')
        lines.append('\t\t</channel>')
    lines += ["\t</server>", "</server>"]
    xml_str = "\r\n".join(lines)
    return b"\xff\xfe" + xml_str.encode("utf-16-le")


CHANNELS = [
    {"name": "일반-1", "ip": "127.0.0.1", "port": 2180},
]


class HttpServerProtocol(asyncio.Protocol):
    def __init__(self):
        self._buf = b""
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport
        peer = transport.get_extra_info("peername")
        logger.debug("HTTP connection from %s", peer)

    def data_received(self, data: bytes):
        self._buf += data
        if b"\r\n\r\n" in self._buf or b"\n\n" in self._buf:
            self.handle_request()

    def handle_request(self):
        try:
            header_part = self._buf.split(b"\r\n\r\n")[0].decode("utf-8", errors="replace")
            first_line = header_part.split("\r\n")[0]
            method, path, *_ = first_line.split(" ")
            logger.info("HTTP %s %s", method, path)

            if path.split("?", 1)[0].lower() == "/serverlist.xml":
                body = build_serverlist(CHANNELS)
                response = (
                    "HTTP/1.0 200 OK\r\n"
                    "Content-Type: text/xml; charset=utf-16\r\n"
                    f"Content-Length: {len(body)}\r\n"
                    "Connection: close\r\n"
                    "\r\n"
                ).encode() + body
            else:
                response = b"HTTP/1.0 404 Not Found\r\nContent-Length: 0\r\n\r\n"

            self.transport.write(response)
        except Exception as e:
            logger.exception("HTTP handler error: %s", e)
        finally:
            self.transport.close()

    def connection_lost(self, exc):
        pass


async def start_http_server(host: str = "0.0.0.0", port: int = 80):
    loop = asyncio.get_running_loop()
    server = await loop.create_server(HttpServerProtocol, host, port)
    logger.info("HTTP server listening on %s:%d (serving /serverlist.xml)", host, port)
    return server
