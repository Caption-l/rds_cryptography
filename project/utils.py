import asyncio
import signal
import sys

YOUR_PROMPT = "\033[32m" + ">>> " + "\033[0m"
THEIR_PROMPT = "\033[31m" + "\n<<< " + "\033[0m"
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 8888


def prompt():
    """Show prompt for message"""
    print(YOUR_PROMPT, end="", flush=True)


def show(msg):
    """Print received message

    Args:
        msg (str|bytes): received message in bytes or decoded str.
    """
    if isinstance(msg, bytes):
        msg = msg.decode()
    print(f"{THEIR_PROMPT}{msg}", flush=True)


async def read_message_from_stdin():
    """Read message to be sent from command line"""
    return await asyncio.get_event_loop().run_in_executor(None, sys.stdin.readline)


async def alice_server(handler):
    loop = asyncio.get_running_loop()
    loop.add_signal_handler(signal.SIGINT, lambda: sys.exit(0))

    # Alice runs the server
    server = await asyncio.start_server(
        lambda r, w: handler(r, w), SERVER_HOST, SERVER_PORT
    )
    async with server:
        await server.serve_forever()


async def bob_client():
    loop = asyncio.get_running_loop()
    loop.add_signal_handler(signal.SIGINT, lambda: sys.exit(0))

    # Bob connects to Alice
    return await asyncio.open_connection(SERVER_HOST, SERVER_PORT)
