#!/usr/bin/env php
<?php
/**
 * cairn-chat: P2P messaging demo (PHP)
 *
 * Usage:
 *   cairn-chat --pair-qr              Display QR code for pairing
 *   cairn-chat --pair-pin             Display PIN code
 *   cairn-chat --pair-link            Display pairing link URI
 *   cairn-chat --enter-pin XXXX-XXXX  Enter PIN code
 *   cairn-chat --from-link <uri>      Accept pairing link
 *   cairn-chat --verbose              Enable structured logging
 */

declare(strict_types=1);

require_once __DIR__ . '/../../php/cairn-p2p/vendor/autoload.php';

use Cairn\Node;
use Cairn\Config;

$options = getopt('', [
    'pair-qr',
    'pair-pin',
    'pair-link',
    'enter-pin:',
    'from-link:',
    'server-mode',
    'send:',
    'peer:',
    'forward',
    'signal:',
    'turn:',
    'verbose',
]);

$verbose = isset($options['verbose']);
$serverMode = isset($options['server-mode']);

// Initialize cairn node
$config = Config::defaults();
if ($serverMode) {
    $node = Node::createServer($config);
} else {
    $node = Node::create($config);
}

$node->start();
fwrite(STDERR, "cairn-chat started. Peer ID: {$node->peerId()}\n");

// Determine pairing mechanism
$mechanism = null;
if (isset($options['pair-qr'])) {
    fwrite(STDERR, "Generating QR code for pairing...\n");
    $mechanism = 'qr';
} elseif (isset($options['pair-pin'])) {
    fwrite(STDERR, "Generating PIN code...\n");
    $mechanism = 'pin';
} elseif (isset($options['pair-link'])) {
    fwrite(STDERR, "Generating pairing link...\n");
    $mechanism = 'link';
} elseif (isset($options['enter-pin'])) {
    $mechanism = 'pin';
} elseif (isset($options['from-link'])) {
    $mechanism = 'link';
} else {
    fwrite(STDERR, "No pairing method. Use --pair-qr, --pair-pin, or --pair-link\n");
    exit(1);
}

try {
    $peerId = $node->pair($mechanism);
    fwrite(STDERR, "Paired with: {$peerId}\n");

    $session = $node->connect($peerId);
    fwrite(STDERR, "Session established.\n");

    // Non-interactive send mode
    if (isset($options['send'])) {
        $session->send('chat', $options['send']);
        fwrite(STDERR, "[sent] {$options['send']}\n");
        $session->close();
        $node->stop();
        exit(0);
    }

    $peerStatus = 'online';

    // Register event handler
    $node->on('event', function (array $event) use (&$peerStatus) {
        switch ($event['type'] ?? '') {
            case 'PeerDisconnected':
                $peerStatus = 'offline';
                fwrite(STDERR, "--- Connection state: Disconnected ---\n");
                break;
            case 'PeerConnected':
                $peerStatus = 'online';
                fwrite(STDERR, "--- Connection state: Connected ---\n");
                break;
            case 'MessageReceived':
                if ($event['channel'] === 'chat') {
                    echo "\r{$event['data']}\n";
                    displayPrompt($peerStatus);
                } elseif ($event['channel'] === 'presence' && $event['data'] === 'typing') {
                    echo "\r[typing...] ";
                }
                break;
        }
    });

    // Interactive chat loop
    displayPrompt($peerStatus);
    $stdin = fopen('php://stdin', 'r');

    while (($line = fgets($stdin)) !== false) {
        $line = trim($line);

        if ($line === '') {
            displayPrompt($peerStatus);
            continue;
        }

        if ($line === '/quit' || $line === '/exit') {
            break;
        }

        if ($line === '/status') {
            fwrite(STDERR, "Peer: {$peerId} | Connected: " . ($session->isConnected() ? 'true' : 'false') . "\n");
            displayPrompt($peerStatus);
            continue;
        }

        $session->send('presence', 'typing');
        $session->send('chat', $line);
        displayPrompt($peerStatus);
    }

    fclose($stdin);
    $session->close();
    $node->stop();

} catch (\Exception $e) {
    displayError($e);
    $node->stop();
    exit(1);
}

function displayPrompt(string $status): void
{
    echo "[{$status}] peer> ";
}

function displayError(\Exception $err): void
{
    fwrite(STDERR, "Error: {$err->getMessage()}\n");
    if (str_contains($err->getMessage(), 'TransportExhausted')) {
        fwrite(STDERR, "Hint: Both peers may be behind symmetric NATs. Deploy a TURN relay.\n");
    }
}
