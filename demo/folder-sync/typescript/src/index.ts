#!/usr/bin/env node
/**
 * cairn-folder-sync: P2P folder synchronization demo (TypeScript)
 *
 * Usage:
 *   cairn-folder-sync --dir ./sync-folder --pair-qr
 *   cairn-folder-sync --dir ./sync-folder --pair-pin
 *   cairn-folder-sync --dir ./sync-folder --pair-link
 *   cairn-folder-sync --dir ./sync-folder --enter-pin XXXX-XXXX
 *   cairn-folder-sync --dir ./sync-folder --from-link <uri>
 *   cairn-folder-sync --dir ./sync-folder --server-hub
 *   cairn-folder-sync --verbose
 */

import { create, createServer } from 'cairn-p2p';
import type { Node, Session, NodeEvent } from 'cairn-p2p';
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';

import { SyncEngine } from './sync';

interface Args {
  dir: string;
  pairQr: boolean;
  pairPin: boolean;
  pairLink: boolean;
  enterPin?: string;
  fromLink?: string;
  serverHub: boolean;
  mesh: boolean;
  verbose: boolean;
}

function parseArgs(): Args {
  const args: Args = {
    dir: '.',
    pairQr: false,
    pairPin: false,
    pairLink: false,
    serverHub: false,
    mesh: false,
    verbose: false,
  };

  const argv = process.argv.slice(2);
  for (let i = 0; i < argv.length; i++) {
    switch (argv[i]) {
      case '--dir': args.dir = argv[++i]; break;
      case '--pair-qr': args.pairQr = true; break;
      case '--pair-pin': args.pairPin = true; break;
      case '--pair-link': args.pairLink = true; break;
      case '--enter-pin': args.enterPin = argv[++i]; break;
      case '--from-link': args.fromLink = argv[++i]; break;
      case '--server-hub': args.serverHub = true; break;
      case '--mesh': args.mesh = true; break;
      case '--verbose': args.verbose = true; break;
    }
  }
  return args;
}

function displayError(err: Error): void {
  console.error(`Error: ${err.message}`);
  if (err.message.includes('TransportExhausted')) {
    console.error('Hint: Both peers may be behind symmetric NATs. Deploy a TURN relay.');
  }
}

async function main(): Promise<void> {
  const args = parseArgs();

  // Validate sync directory
  const syncDir = path.resolve(args.dir);
  if (!fs.existsSync(syncDir)) {
    fs.mkdirSync(syncDir, { recursive: true });
    console.error(`Created sync directory: ${syncDir}`);
  }

  // Initialize cairn node
  const config: Record<string, unknown> = {};
  if (args.mesh) {
    config.mesh_enabled = true;
    config.max_hops = 3;
    config.relay_willing = true;
  }

  const node: Node = args.serverHub
    ? createServer(config)
    : create(config);

  await node.start();
  console.error(`cairn-folder-sync started. Watching: ${syncDir}`);

  // Determine pairing mechanism
  let mechanism: string | undefined;
  if (args.pairQr) {
    console.error('Generating QR code for pairing...');
    mechanism = 'qr';
  } else if (args.pairPin) {
    console.error('Generating PIN code...');
    mechanism = 'pin';
  } else if (args.pairLink) {
    console.error('Generating pairing link...');
    mechanism = 'link';
  } else if (args.enterPin) {
    mechanism = 'pin';
  } else if (args.fromLink) {
    mechanism = 'link';
  }

  if (!mechanism) {
    console.error('No pairing method. Use --pair-qr, --pair-pin, or --pair-link');
    process.exit(1);
  }

  try {
    const peerId = await node.pair(mechanism);
    console.error(`Paired with: ${peerId}`);

    const session: Session = await node.connect(peerId);
    console.error('Sync session established.');

    const engine = new SyncEngine(syncDir, 65536);

    // Initial directory scan
    const localFiles = engine.scanDirectory();
    console.error(`Found ${localFiles.length} files to sync`);

    // Send file metadata to peer
    for (const meta of localFiles) {
      const metaBytes = Buffer.from(JSON.stringify(meta));
      await session.send('sync', metaBytes);
    }

    // Listen for sync events
    node.on('event', async (event: NodeEvent) => {
      switch (event.type) {
        case 'MessageReceived':
          if (event.channel === 'sync') {
            await handleSyncMessage(event.data, syncDir, session, engine);
          }
          break;
        case 'PeerDisconnected':
          console.error('--- Connection state: Disconnected ---');
          break;
        case 'PeerConnected':
          console.error('--- Connection state: Connected ---');
          break;
      }
    });

    console.error('Watching for changes... (Ctrl+C to stop)');

    // Watch directory for changes
    const watcher = fs.watch(syncDir, { recursive: true }, async (eventType, filename) => {
      if (!filename || filename.startsWith('.')) return;

      const filePath = path.join(syncDir, filename);
      if (!fs.existsSync(filePath) || !fs.statSync(filePath).isFile()) return;

      console.error(`[change] ${filename}`);
      const meta = engine.computeFileMeta(filePath, syncDir);
      if (meta) {
        await session.send('sync', Buffer.from(JSON.stringify(meta)));
      }
    });

    // Keep running until interrupted
    process.on('SIGINT', async () => {
      console.error('\nShutting down...');
      watcher.close();
      await session.close();
      await node.stop();
      process.exit(0);
    });

  } catch (err) {
    displayError(err as Error);
    await node.stop();
    process.exit(1);
  }
}

async function handleSyncMessage(
  data: Uint8Array,
  syncDir: string,
  session: Session,
  engine: SyncEngine,
): Promise<void> {
  const text = Buffer.from(data).toString('utf-8');
  let msg: Record<string, unknown>;

  try {
    msg = JSON.parse(text);
  } catch {
    return;
  }

  // File metadata message
  if (msg.path && msg.hash && msg.size !== undefined) {
    const remoteMeta = msg as unknown as {
      path: string;
      hash: string;
      size: number;
      modified: number;
      peer_id_prefix: string;
    };

    console.error(`[sync] Received metadata: ${remoteMeta.path} (${remoteMeta.size} bytes)`);

    const localMeta = engine.getFileMeta(remoteMeta.path);
    if (localMeta && localMeta.hash !== remoteMeta.hash && localMeta.modified !== remoteMeta.modified) {
      const conflictPath = engine.resolveConflictPath(
        remoteMeta.path,
        remoteMeta.peer_id_prefix || 'unknown',
        remoteMeta.modified,
      );
      console.error(`[conflict] ${remoteMeta.path} — preserved as ${conflictPath}`);
    }

    // Request chunks
    const request = {
      type: 'chunk_request',
      file_path: remoteMeta.path,
      file_hash: remoteMeta.hash,
      from_chunk: engine.lastReceivedChunk(remoteMeta.path),
    };
    await session.send('sync', Buffer.from(JSON.stringify(request)));
    return;
  }

  // Chunk data message
  if (msg.file_path && msg.chunk_index !== undefined && msg.chunk_data) {
    const chunk = msg as unknown as {
      file_path: string;
      file_hash: string;
      chunk_index: number;
      chunk_count: number;
      chunk_data: string;
    };

    const destPath = path.join(syncDir, chunk.file_path);
    const destDir = path.dirname(destPath);
    if (!fs.existsSync(destDir)) {
      fs.mkdirSync(destDir, { recursive: true });
    }

    const chunkBytes = Buffer.from(chunk.chunk_data, 'base64');
    engine.writeChunk(destPath, chunk.chunk_index, chunkBytes);
    engine.recordChunk(chunk.file_path, chunk.chunk_index);

    if (chunk.chunk_index + 1 === chunk.chunk_count) {
      console.error(`[sync] Completed: ${chunk.file_path}`);
      engine.markComplete(chunk.file_path, chunk.file_hash);

      const ack = {
        type: 'chunk_ack',
        file_path: chunk.file_path,
        file_hash: chunk.file_hash,
      };
      await session.send('sync', Buffer.from(JSON.stringify(ack)));
    }
    return;
  }

  // Chunk request message
  if (msg.type === 'chunk_request' && msg.file_path) {
    const req = msg as { file_path: string; file_hash: string; from_chunk: number };
    const filePath = path.join(syncDir, req.file_path);

    if (!fs.existsSync(filePath)) return;

    const chunks = engine.splitFile(filePath, req.file_path);
    const startFrom = req.from_chunk || 0;

    for (let i = startFrom; i < chunks.length; i++) {
      await session.send('sync', Buffer.from(JSON.stringify(chunks[i])));
    }
  }
}

main().catch(console.error);
