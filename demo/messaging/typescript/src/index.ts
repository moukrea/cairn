#!/usr/bin/env node
/**
 * cairn-chat: P2P messaging demo (TypeScript)
 *
 * Usage:
 *   cairn-chat --pair-qr              Display QR code for pairing
 *   cairn-chat --pair-pin             Display PIN code
 *   cairn-chat --pair-link            Display pairing link URI
 *   cairn-chat --enter-pin XXXX-XXXX  Enter PIN code
 *   cairn-chat --from-link <uri>      Accept pairing link
 *   cairn-chat --verbose              Enable structured logging
 */

import { create, createServer } from 'cairn-p2p';
import type { Node, Session, NodeEvent } from 'cairn-p2p';
import * as readline from 'readline';

interface Args {
  pairQr: boolean;
  pairPin: boolean;
  pairLink: boolean;
  enterPin?: string;
  fromLink?: string;
  serverMode: boolean;
  send?: string;
  peer?: string;
  forward: boolean;
  signal?: string;
  turn?: string;
  verbose: boolean;
}

function parseArgs(): Args {
  const args: Args = {
    pairQr: false,
    pairPin: false,
    pairLink: false,
    serverMode: false,
    forward: false,
    verbose: false,
  };

  const argv = process.argv.slice(2);
  for (let i = 0; i < argv.length; i++) {
    switch (argv[i]) {
      case '--pair-qr': args.pairQr = true; break;
      case '--pair-pin': args.pairPin = true; break;
      case '--pair-link': args.pairLink = true; break;
      case '--enter-pin': args.enterPin = argv[++i]; break;
      case '--from-link': args.fromLink = argv[++i]; break;
      case '--server-mode': args.serverMode = true; break;
      case '--send': args.send = argv[++i]; break;
      case '--peer': args.peer = argv[++i]; break;
      case '--forward': args.forward = true; break;
      case '--signal': args.signal = argv[++i]; break;
      case '--turn': args.turn = argv[++i]; break;
      case '--verbose': args.verbose = true; break;
    }
  }
  return args;
}

function displayPrompt(peerStatus: string): void {
  process.stdout.write(`[${peerStatus}] peer> `);
}

function displayMessage(sender: string, text: string, queued: boolean): void {
  const prefix = queued ? '[queued] ' : '';
  console.log(`\r${prefix}${sender}: ${text}`);
}

function displayStateChange(state: string): void {
  console.error(`--- Connection state: ${state} ---`);
}

function displayError(err: Error): void {
  console.error(`Error: ${err.message}`);
  if (err.message.includes('TransportExhausted')) {
    console.error('Hint: Both peers may be behind symmetric NATs. Deploy a TURN relay to resolve.');
  }
}

async function main(): Promise<void> {
  const args = parseArgs();

  // Initialize cairn node
  const node: Node = args.serverMode
    ? createServer({})
    : create({});

  await node.start();
  console.error(`cairn-chat started. Peer ID: ${node.peerId()}`);

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
    console.error('No pairing method specified. Use --pair-qr, --pair-pin, or --pair-link');
    process.exit(1);
  }

  try {
    const peerId = await node.pair(mechanism);
    console.error(`Paired with: ${peerId}`);

    const session: Session = await node.connect(peerId);
    console.error('Session established.');

    // Listen for events
    let peerStatus = 'online';
    node.on('event', (event: NodeEvent) => {
      switch (event.type) {
        case 'PeerDisconnected':
          peerStatus = 'offline';
          displayStateChange('Disconnected');
          break;
        case 'PeerConnected':
          peerStatus = 'online';
          displayStateChange('Connected');
          break;
        case 'MessageReceived':
          if (event.channel === 'chat') {
            const text = Buffer.from(event.data).toString('utf-8');
            displayMessage('peer', text, false);
            displayPrompt(peerStatus);
          } else if (event.channel === 'presence') {
            const indicator = Buffer.from(event.data).toString('utf-8');
            if (indicator === 'typing') {
              process.stdout.write('\r[typing...] ');
              setTimeout(() => displayPrompt(peerStatus), 5000);
            }
          }
          break;
        case 'Error':
          displayError(new Error(event.message || 'Unknown error'));
          break;
      }
    });

    // Non-interactive send mode
    if (args.send) {
      await session.send('chat', Buffer.from(args.send));
      console.error(`[sent] ${args.send}`);
      await session.close();
      await node.stop();
      return;
    }

    // Interactive chat loop
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
      terminal: false,
    });

    displayPrompt(peerStatus);

    rl.on('line', async (line: string) => {
      if (!line.trim()) {
        displayPrompt(peerStatus);
        return;
      }

      if (line === '/quit' || line === '/exit') {
        await session.close();
        await node.stop();
        process.exit(0);
      }

      if (line === '/status') {
        console.error(`Peer: ${peerId} | Connected: ${session.isConnected()}`);
        displayPrompt(peerStatus);
        return;
      }

      // Send typing indicator then message
      await session.send('presence', Buffer.from('typing'));
      await session.send('chat', Buffer.from(line));
      displayPrompt(peerStatus);
    });

    rl.on('close', async () => {
      await session.close();
      await node.stop();
    });

  } catch (err) {
    displayError(err as Error);
    await node.stop();
    process.exit(1);
  }
}

main().catch(console.error);
