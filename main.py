import argparse
import asyncio
import logging
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))


def setup_logging(debug: bool = False):
    level = logging.DEBUG if debug else logging.INFO
    fmt = "%(asctime)s [%(name)-14s] %(levelname)-8s %(message)s"
    logging.basicConfig(level=level, format=fmt, datefmt="%H:%M:%S")

async def run_servers():
    from src.network.login_server import start_login_server
    from src.network.game_server import start_game_server
    from src.network.http_server import start_http_server
    from src.network.udp_server import start_udp_server

    http_srv = await start_http_server("0.0.0.0", 80)
    login_srv = await start_login_server("0.0.0.0", 2180)
    game_srv = await start_game_server("0.0.0.0", 2181)
    udp_login_transport, _udp_login = await start_udp_server("0.0.0.0", 2180, "login")
    udp_game_transport, _udp_game = await start_udp_server("0.0.0.0", 2181, "game")

    print("=" * 50)
    print("  Raycity \033[38;2;55;118;171mPython\033[0m 1.325 Emulator")
    print("=" * 50)

    try:
        async with http_srv, login_srv, game_srv:
            await asyncio.gather(
                http_srv.serve_forever(),
                login_srv.serve_forever(),
                game_srv.serve_forever(),
            )
    finally:
        udp_login_transport.close()
        udp_game_transport.close()

def main():
    parser = argparse.ArgumentParser(description="Raycity Python 1.325 Emulator")
    parser.add_argument("--debug", action="store_true",
                        help="Enable debug logging")
    args = parser.parse_args()
    setup_logging(args.debug)
    asyncio.run(run_servers())

if __name__ == "__main__":
    main()
