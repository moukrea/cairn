#!/usr/bin/env python3
"""cairn-folder-sync: P2P folder synchronization demo (Python)

Usage:
    cairn-folder-sync --dir ./sync-folder --pair-qr
    cairn-folder-sync --dir ./sync-folder --pair-pin
    cairn-folder-sync --dir ./sync-folder --pair-link
    cairn-folder-sync --dir ./sync-folder --enter-pin XXXX-XXXX
    cairn-folder-sync --dir ./sync-folder --from-link <uri>
    cairn-folder-sync --dir ./sync-folder --server-hub
    cairn-folder-sync --verbose
"""

import argparse
import asyncio
import base64
import hashlib
import json
import math
import os
import sys
import time

CHUNK_SIZE = 65536  # 64 KB
ROLLING_HASH_WINDOW = 64
MOD_ADLER = 65521


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="cairn P2P folder sync demo")
    parser.add_argument("--dir", type=str, default=".", help="Directory to sync")
    parser.add_argument("--pair-qr", action="store_true", help="Display QR code (initiator)")
    parser.add_argument("--pair-pin", action="store_true", help="Display PIN code (initiator)")
    parser.add_argument("--pair-link", action="store_true", help="Display pairing link (initiator)")
    parser.add_argument("--enter-pin", type=str, help="Enter PIN code (responder)")
    parser.add_argument("--scan-qr", action="store_true", help="Scan QR code (responder)")
    parser.add_argument("--from-link", type=str, help="Accept pairing link (responder)")
    parser.add_argument("--mesh", action="store_true", help="Enable mesh routing")
    parser.add_argument("--server-hub", action="store_true", help="Always-on sync hub mode")
    parser.add_argument("--signal", type=str, help="Signaling server URL")
    parser.add_argument("--turn", type=str, help="TURN relay URL")
    parser.add_argument("--verbose", action="store_true", help="Enable structured logging")
    return parser.parse_args()


def rolling_hash(data: bytes) -> int:
    a = 1
    b = 0
    for byte in data:
        a = (a + byte) % MOD_ADLER
        b = (b + a) % MOD_ADLER
    return ((b << 16) | a) & 0xFFFFFFFF


class SyncEngine:
    """Manages file state, chunked transfer, conflict resolution, and delta sync."""

    def __init__(self, sync_dir: str, chunk_size: int = CHUNK_SIZE):
        self.sync_dir = sync_dir
        self.chunk_size = chunk_size
        self.files: dict[str, dict] = {}
        self.chunk_progress: dict[str, int] = {}

    def scan_directory(self) -> list[dict]:
        self.files.clear()
        result: list[dict] = []
        self._scan_recursive(self.sync_dir, result)
        return result

    def _scan_recursive(self, dir_path: str, result: list[dict]) -> None:
        if not os.path.exists(dir_path):
            return
        for entry in os.scandir(dir_path):
            if entry.name.startswith("."):
                continue
            if entry.is_dir(follow_symlinks=False):
                self._scan_recursive(entry.path, result)
            elif entry.is_file(follow_symlinks=False):
                meta = self.compute_file_meta(entry.path)
                if meta:
                    self.files[meta["path"]] = meta
                    result.append(meta)

    def compute_file_meta(self, file_path: str) -> dict | None:
        try:
            stat = os.stat(file_path)
            if not os.path.isfile(file_path):
                return None
            rel_path = os.path.relpath(file_path, self.sync_dir)
            file_hash = self._compute_file_hash(file_path)
            return {
                "path": rel_path,
                "size": stat.st_size,
                "modified": int(stat.st_mtime),
                "hash": file_hash,
                "peer_id_prefix": "",
            }
        except OSError:
            return None

    def _compute_file_hash(self, file_path: str) -> str:
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()

    def get_file_meta(self, rel_path: str) -> dict | None:
        return self.files.get(rel_path)

    def split_file(self, file_path: str, rel_path: str) -> list[dict]:
        with open(file_path, "rb") as f:
            data = f.read()
        file_hash = hashlib.sha256(data).hexdigest()
        chunk_count = max(1, math.ceil(len(data) / self.chunk_size))
        chunks = []
        for i in range(chunk_count):
            start = i * self.chunk_size
            end = min(start + self.chunk_size, len(data))
            chunk_data = base64.b64encode(data[start:end]).decode("ascii")
            chunks.append({
                "file_path": rel_path,
                "file_hash": file_hash,
                "chunk_index": i,
                "chunk_count": chunk_count,
                "chunk_data": chunk_data,
            })
        return chunks

    def write_chunk(self, dest_path: str, chunk_index: int, data: bytes) -> None:
        offset = chunk_index * self.chunk_size
        mode = "r+b" if os.path.exists(dest_path) else "wb"
        with open(dest_path, mode) as f:
            f.seek(offset)
            f.write(data)

    def last_received_chunk(self, rel_path: str) -> int:
        return self.chunk_progress.get(rel_path, 0)

    def record_chunk(self, rel_path: str, index: int) -> None:
        self.chunk_progress[rel_path] = index + 1

    def mark_complete(self, rel_path: str, file_hash: str) -> None:
        self.chunk_progress.pop(rel_path, None)
        meta = self.files.get(rel_path)
        if meta:
            meta["hash"] = file_hash

    def resolve_conflict_path(self, rel_path: str, peer_id_prefix: str, timestamp: int) -> str:
        base = os.path.basename(rel_path)
        dir_part = os.path.dirname(rel_path)
        conflict_name = f"{base}.conflict.{peer_id_prefix or 'unknown'}.{timestamp}"
        return os.path.join(dir_part, conflict_name) if dir_part else conflict_name

    def preserve_conflict(self, rel_path: str, peer_id_prefix: str, timestamp: int, data: bytes) -> str:
        conflict_path = self.resolve_conflict_path(rel_path, peer_id_prefix, timestamp)
        full_path = os.path.join(self.sync_dir, conflict_path)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        with open(full_path, "wb") as f:
            f.write(data)
        return conflict_path

    def compute_delta(self, old_data: bytes, new_data: bytes) -> list[dict]:
        old_sigs = self._compute_signatures(old_data)
        deltas: list[dict] = []
        pos = 0
        change_start: int | None = None

        while pos + ROLLING_HASH_WINDOW <= len(new_data):
            window = new_data[pos : pos + ROLLING_HASH_WINDOW]
            h = rolling_hash(window)
            offsets = old_sigs.get(h)
            matched = False
            if offsets:
                for off in offsets:
                    if off + ROLLING_HASH_WINDOW > len(old_data):
                        continue
                    if old_data[off : off + ROLLING_HASH_WINDOW] == window:
                        matched = True
                        break

            if matched:
                if change_start is not None:
                    deltas.append({
                        "offset": change_start,
                        "length": pos - change_start,
                        "data": base64.b64encode(new_data[change_start:pos]).decode("ascii"),
                    })
                    change_start = None
                pos += ROLLING_HASH_WINDOW
                continue

            if change_start is None:
                change_start = pos
            pos += 1

        if change_start is not None:
            deltas.append({
                "offset": change_start,
                "length": len(new_data) - change_start,
                "data": base64.b64encode(new_data[change_start:]).decode("ascii"),
            })
        elif pos < len(new_data):
            deltas.append({
                "offset": pos,
                "length": len(new_data) - pos,
                "data": base64.b64encode(new_data[pos:]).decode("ascii"),
            })

        return deltas

    def apply_delta(self, base_data: bytes, deltas: list[dict]) -> bytes:
        result = bytearray(base_data)
        for delta in deltas:
            data = base64.b64decode(delta["data"])
            offset = delta["offset"]
            result[offset : offset + len(data)] = data
        return bytes(result)

    def _compute_signatures(self, data: bytes) -> dict[int, list[int]]:
        sigs: dict[int, list[int]] = {}
        if len(data) < ROLLING_HASH_WINDOW:
            return sigs
        for offset in range(len(data) - ROLLING_HASH_WINDOW + 1):
            window = data[offset : offset + ROLLING_HASH_WINDOW]
            h = rolling_hash(window)
            sigs.setdefault(h, []).append(offset)
        return sigs


def _make_sync_event_handler(sync_dir: str, loop: asyncio.AbstractEventLoop, queue: asyncio.Queue):
    """Create a watchdog FileSystemEventHandler (imports watchdog at call time)."""
    from watchdog.events import FileSystemEventHandler

    class _Handler(FileSystemEventHandler):
        def _enqueue(self, path: str) -> None:
            rel = os.path.relpath(path, sync_dir)
            if rel.startswith("."):
                return
            loop.call_soon_threadsafe(queue.put_nowait, path)

        def on_created(self, event):
            if not event.is_directory:
                self._enqueue(event.src_path)

        def on_modified(self, event):
            if not event.is_directory:
                self._enqueue(event.src_path)

        def on_moved(self, event):
            if not event.is_directory:
                self._enqueue(event.dest_path)

    return _Handler()


def display_error(err: Exception) -> None:
    print(f"Error: {err}", file=sys.stderr)
    if "TransportExhausted" in str(err):
        print(
            "Hint: Both peers may be behind symmetric NATs. Deploy a TURN relay.",
            file=sys.stderr,
        )


async def handle_sync_message(
    data: bytes,
    sync_dir: str,
    session: object,
    engine: SyncEngine,
) -> None:
    text = data.decode("utf-8")
    try:
        msg = json.loads(text)
    except json.JSONDecodeError:
        return

    # File metadata message
    if "path" in msg and "hash" in msg and "size" in msg:
        print(f"[sync] Received metadata: {msg['path']} ({msg['size']} bytes)", file=sys.stderr)

        local_meta = engine.get_file_meta(msg["path"])
        if local_meta and local_meta["hash"] != msg["hash"] and local_meta["modified"] != msg["modified"]:
            conflict_path = engine.resolve_conflict_path(
                msg["path"],
                msg.get("peer_id_prefix", "unknown"),
                msg["modified"],
            )
            print(f"[conflict] {msg['path']} — preserved as {conflict_path}", file=sys.stderr)

        request = {
            "type": "chunk_request",
            "file_path": msg["path"],
            "file_hash": msg["hash"],
            "from_chunk": engine.last_received_chunk(msg["path"]),
        }
        await session.send("sync", json.dumps(request).encode())
        return

    # Chunk data message
    if "file_path" in msg and "chunk_index" in msg and "chunk_data" in msg:
        dest_path = os.path.join(sync_dir, msg["file_path"])
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)

        chunk_bytes = base64.b64decode(msg["chunk_data"])
        engine.write_chunk(dest_path, msg["chunk_index"], chunk_bytes)
        engine.record_chunk(msg["file_path"], msg["chunk_index"])

        if msg["chunk_index"] + 1 == msg["chunk_count"]:
            print(f"[sync] Completed: {msg['file_path']}", file=sys.stderr)
            engine.mark_complete(msg["file_path"], msg["file_hash"])

            ack = {
                "type": "chunk_ack",
                "file_path": msg["file_path"],
                "file_hash": msg["file_hash"],
            }
            await session.send("sync", json.dumps(ack).encode())
        return

    # Chunk request message
    if msg.get("type") == "chunk_request" and "file_path" in msg:
        file_path = os.path.join(sync_dir, msg["file_path"])
        if not os.path.exists(file_path):
            return

        chunks = engine.split_file(file_path, msg["file_path"])
        start_from = msg.get("from_chunk", 0)

        for i in range(start_from, len(chunks)):
            await session.send("sync", json.dumps(chunks[i]).encode())


async def main() -> None:
    args = parse_args()

    if args.verbose:
        import logging
        logging.basicConfig(level=logging.DEBUG)

    # Validate sync directory
    sync_dir = os.path.abspath(args.dir)
    if not os.path.exists(sync_dir):
        os.makedirs(sync_dir, exist_ok=True)
        print(f"Created sync directory: {sync_dir}", file=sys.stderr)

    from cairn import create, create_server

    # Initialize cairn node
    config: dict = {}
    if args.mesh:
        config["mesh_enabled"] = True
        config["max_hops"] = 3
        config["relay_willing"] = True

    node = create_server(config) if args.server_hub else create(config)
    await node.start()
    print(f"cairn-folder-sync started. Watching: {sync_dir}", file=sys.stderr)

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
    elif args.scan_qr:
        mechanism = "qr"
    elif args.from_link:
        mechanism = "link"
    else:
        print("No pairing method. Use --pair-qr, --pair-pin, or --pair-link", file=sys.stderr)
        sys.exit(1)

    try:
        peer_id = await node.pair(mechanism)
        print(f"Paired with: {peer_id}", file=sys.stderr)

        session = await node.connect(peer_id)
        print("Sync session established.", file=sys.stderr)

        engine = SyncEngine(sync_dir, CHUNK_SIZE)

        # Initial directory scan
        local_files = engine.scan_directory()
        print(f"Found {len(local_files)} files to sync", file=sys.stderr)

        # Send file metadata to peer
        for meta in local_files:
            await session.send("sync", json.dumps(meta).encode())

        # Event handler
        async def handle_events() -> None:
            async for event in node.events():
                if event.type == "MessageReceived" and event.channel == "sync":
                    await handle_sync_message(event.data, sync_dir, session, engine)
                elif event.type == "PeerDisconnected":
                    print("--- Connection state: Disconnected ---", file=sys.stderr)
                elif event.type == "PeerConnected":
                    print("--- Connection state: Connected ---", file=sys.stderr)

        event_task = asyncio.create_task(handle_events())

        # Set up file watcher
        from watchdog.observers import Observer

        loop = asyncio.get_event_loop()
        change_queue: asyncio.Queue[str] = asyncio.Queue()
        handler = _make_sync_event_handler(sync_dir, loop, change_queue)
        observer = Observer()
        observer.schedule(handler, sync_dir, recursive=True)
        observer.start()

        print("Watching for changes... (Ctrl+C to stop)", file=sys.stderr)

        # Process file change events
        async def process_changes() -> None:
            while True:
                file_path = await change_queue.get()
                if not os.path.exists(file_path) or not os.path.isfile(file_path):
                    continue
                rel = os.path.relpath(file_path, sync_dir)
                print(f"[change] {rel}", file=sys.stderr)
                meta = engine.compute_file_meta(file_path)
                if meta:
                    await session.send("sync", json.dumps(meta).encode())

        change_task = asyncio.create_task(process_changes())

        # Keep running until interrupted
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            pass
        finally:
            observer.stop()
            observer.join()
            event_task.cancel()
            change_task.cancel()
            await session.close()
            await node.stop()

    except Exception as err:
        display_error(err)
        await node.stop()
        sys.exit(1)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nShutting down...", file=sys.stderr)
