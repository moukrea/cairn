#!/usr/bin/env python3
"""cairn-chat: P2P messaging demo (Python)

Usage:
    cairn-chat --pair-qr              Display QR code for pairing
    cairn-chat --pair-pin             Display PIN code
    cairn-chat --pair-link            Display pairing link URI
    cairn-chat --enter-pin XXXX-XXXX  Enter PIN code
    cairn-chat --from-link <uri>      Accept pairing link
    cairn-chat --verbose              Enable structured logging
"""

import argparse
import asyncio
import sys

from cairn import create, create_server


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="cairn P2P messaging demo")
    parser.add_argument("--pair-qr", action="store_true", help="Display QR code (initiator)")
    parser.add_argument("--pair-pin", action="store_true", help="Display PIN code (initiator)")
    parser.add_argument("--pair-link", action="store_true", help="Display pairing link (initiator)")
    parser.add_argument("--enter-pin", type=str, help="Enter PIN code (responder)")
    parser.add_argument("--from-link", type=str, help="Accept pairing link (responder)")
    parser.add_argument("--server-mode", action="store_true", help="Run as server-mode peer")
    parser.add_argument("--send", type=str, help="Send message (non-interactive)")
    parser.add_argument("--peer", type=str, help="Target peer ID for --send")
    parser.add_argument("--forward", action="store_true", help="Forward via server")
    parser.add_argument("--signal", type=str, help="Signaling server URL")
    parser.add_argument("--turn", type=str, help="TURN relay URL")
    parser.add_argument("--verbose", action="store_true", help="Enable structured logging")
    return parser.parse_args()


def display_prompt(peer_status: str) -> None:
    print(f"[{peer_status}] peer> ", end="", flush=True)


def display_message(sender: str, text: str, queued: bool = False) -> None:
    prefix = "[queued] " if queued else ""
    print(f"\r{prefix}{sender}: {text}")


def display_state_change(state: str) -> None:
    print(f"--- Connection state: {state} ---", file=sys.stderr)


def display_error(err: Exception) -> None:
    print(f"Error: {err}", file=sys.stderr)
    if "TransportExhausted" in str(err):
        print(
            "Hint: Both peers may be behind symmetric NATs. Deploy a TURN relay.",
            file=sys.stderr,
        )


async def main() -> None:
    args = parse_args()

    if args.verbose:
        import logging
        logging.basicConfig(level=logging.DEBUG)

    # Initialize cairn node
    if args.server_mode:
        node = create_server({})
    else:
        node = create({})

    await node.start()
    print(f"cairn-chat started. Peer ID: {node.peer_id()}", file=sys.stderr)

    # Determine pairing mechanism
    mechanism = None
    if args.pair_qr:
        print("Generating QR code for pairing...", file=sys.stderr)
        mechanism = "qr"
    elif args.pair_pin:
        print("Generating PIN code...", file=sys.stderr)
        mechanism = "pin"
    elif args.pair_link:
        print("Generating pairing link...", file=sys.stderr)
        mechanism = "link"
    elif args.enter_pin:
        mechanism = "pin"
    elif args.from_link:
        mechanism = "link"
    else:
        print("No pairing method. Use --pair-qr, --pair-pin, or --pair-link", file=sys.stderr)
        sys.exit(1)

    try:
        peer_id = await node.pair(mechanism)
        print(f"Paired with: {peer_id}", file=sys.stderr)

        session = await node.connect(peer_id)
        print("Session established.", file=sys.stderr)

        peer_status = "online"

        # Event handler
        async def handle_events() -> None:
            nonlocal peer_status
            async for event in node.events():
                if event.type == "PeerDisconnected":
                    peer_status = "offline"
                    display_state_change("Disconnected")
                elif event.type == "PeerConnected":
                    peer_status = "online"
                    display_state_change("Connected")
                elif event.type == "MessageReceived":
                    if event.channel == "chat":
                        text = event.data.decode("utf-8")
                        display_message("peer", text)
                        display_prompt(peer_status)
                    elif event.channel == "presence":
                        if event.data == b"typing":
                            print("\r[typing...] ", end="", flush=True)

        event_task = asyncio.create_task(handle_events())

        # Non-interactive send
        if args.send:
            await session.send("chat", args.send.encode())
            print(f"[sent] {args.send}", file=sys.stderr)
            await session.close()
            await node.stop()
            return

        # Interactive loop
        display_prompt(peer_status)
        loop = asyncio.get_event_loop()
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await loop.connect_read_pipe(lambda: protocol, sys.stdin)

        while True:
            line_bytes = await reader.readline()
            if not line_bytes:
                break
            line = line_bytes.decode().strip()

            if not line:
                display_prompt(peer_status)
                continue

            if line in ("/quit", "/exit"):
                break

            if line == "/status":
                print(
                    f"Peer: {peer_id} | Connected: {session.is_connected()}",
                    file=sys.stderr,
                )
                display_prompt(peer_status)
                continue

            await session.send("presence", b"typing")
            await session.send("chat", line.encode())
            display_prompt(peer_status)

        event_task.cancel()
        await session.close()
        await node.stop()

    except Exception as err:
        display_error(err)
        await node.stop()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
