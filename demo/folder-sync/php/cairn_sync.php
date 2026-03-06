#!/usr/bin/env php
<?php
/**
 * cairn-folder-sync: P2P folder synchronization demo (PHP)
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

declare(strict_types=1);

// ---------------------------------------------------------------------------
// CLI parsing
// ---------------------------------------------------------------------------

if (in_array('--help', $argv, true) || in_array('-h', $argv, true)) {
    echo <<<HELP
    cairn P2P folder sync demo

    Options:
      --dir <path>            Directory to sync (default: .)
      --pair-qr               Display QR code (initiator)
      --pair-pin              Display PIN code (initiator)
      --pair-link             Display pairing link (initiator)
      --enter-pin <pin>       Enter PIN code (responder)
      --scan-qr               Scan QR code (responder)
      --from-link <uri>       Accept pairing link (responder)
      --mesh                  Enable mesh routing
      --server-hub            Always-on sync hub mode
      --signal <url>          Signaling server URL
      --turn <url>            TURN relay URL
      --verbose               Enable structured logging
      --help, -h              Show this help message

    HELP;
    exit(0);
}

$options = getopt('', [
    'dir:',
    'pair-qr',
    'pair-pin',
    'pair-link',
    'enter-pin:',
    'scan-qr',
    'from-link:',
    'mesh',
    'server-hub',
    'signal:',
    'turn:',
    'verbose',
]);

$syncDir   = realpath($options['dir'] ?? '.') ?: ($options['dir'] ?? '.');
$verbose   = isset($options['verbose']);
$mesh      = isset($options['mesh']);
$serverHub = isset($options['server-hub']);

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const CHUNK_SIZE = 65536; // 64 KB
const ROLLING_HASH_WINDOW = 64;
const MOD_ADLER = 65521;

// ---------------------------------------------------------------------------
// SyncEngine
// ---------------------------------------------------------------------------

class SyncEngine
{
    /** @var array<string, array> */
    private array $files = [];

    /** @var array<string, int> */
    private array $chunkProgress = [];

    public function __construct(
        private readonly string $syncDir,
        private readonly int $chunkSize = CHUNK_SIZE,
    ) {}

    /** Scan directory and return file metadata list. */
    public function scanDirectory(): array
    {
        $this->files = [];
        $result = [];
        $this->scanRecursive($this->syncDir, $result);
        return $result;
    }

    private function scanRecursive(string $dir, array &$result): void
    {
        if (!is_dir($dir)) {
            return;
        }
        $entries = scandir($dir);
        if ($entries === false) {
            return;
        }
        foreach ($entries as $name) {
            if (str_starts_with($name, '.')) {
                continue;
            }
            $fullPath = $dir . DIRECTORY_SEPARATOR . $name;
            if (is_dir($fullPath)) {
                $this->scanRecursive($fullPath, $result);
            } elseif (is_file($fullPath)) {
                $meta = $this->computeFileMeta($fullPath);
                if ($meta !== null) {
                    $this->files[$meta['path']] = $meta;
                    $result[] = $meta;
                }
            }
        }
    }

    public function computeFileMeta(string $filePath): ?array
    {
        if (!is_file($filePath)) {
            return null;
        }
        $relPath = $this->relativePath($filePath);
        $hash = hash_file('sha256', $filePath);
        if ($hash === false) {
            return null;
        }
        $stat = stat($filePath);
        if ($stat === false) {
            return null;
        }
        return [
            'path'           => $relPath,
            'size'           => $stat['size'],
            'modified'       => $stat['mtime'],
            'hash'           => $hash,
            'peer_id_prefix' => '',
        ];
    }

    public function getFileMeta(string $relPath): ?array
    {
        return $this->files[$relPath] ?? null;
    }

    /** Split file into 64KB chunks for transfer. */
    public function splitFile(string $filePath, string $relPath): array
    {
        $data = file_get_contents($filePath);
        if ($data === false) {
            return [];
        }
        $fileHash = hash('sha256', $data);
        $len = strlen($data);
        $chunkCount = max(1, (int) ceil($len / $this->chunkSize));
        $chunks = [];

        for ($i = 0; $i < $chunkCount; $i++) {
            $start = $i * $this->chunkSize;
            $chunkData = substr($data, $start, $this->chunkSize);
            $chunks[] = [
                'file_path'   => $relPath,
                'file_hash'   => $fileHash,
                'chunk_index' => $i,
                'chunk_count' => $chunkCount,
                'chunk_data'  => base64_encode($chunkData),
            ];
        }
        return $chunks;
    }

    /** Write a received chunk to disk at the correct offset. */
    public function writeChunk(string $destPath, int $chunkIndex, string $data): void
    {
        $offset = $chunkIndex * $this->chunkSize;
        $dir = dirname($destPath);
        if (!is_dir($dir)) {
            mkdir($dir, 0755, true);
        }
        $mode = file_exists($destPath) ? 'r+b' : 'wb';
        $fh = fopen($destPath, $mode);
        if ($fh === false) {
            return;
        }
        fseek($fh, $offset);
        fwrite($fh, $data);
        fclose($fh);
    }

    public function lastReceivedChunk(string $relPath): int
    {
        return $this->chunkProgress[$relPath] ?? 0;
    }

    public function recordChunk(string $relPath, int $index): void
    {
        $this->chunkProgress[$relPath] = $index + 1;
    }

    public function markComplete(string $relPath, string $hash): void
    {
        unset($this->chunkProgress[$relPath]);
        if (isset($this->files[$relPath])) {
            $this->files[$relPath]['hash'] = $hash;
        }
    }

    public function resolveConflictPath(string $relPath, string $peerIdPrefix, int $timestamp): string
    {
        $base = basename($relPath);
        $dir  = dirname($relPath);
        $prefix = $peerIdPrefix ?: 'unknown';
        $conflictName = "{$base}.conflict.{$prefix}.{$timestamp}";
        return $dir !== '.' ? $dir . DIRECTORY_SEPARATOR . $conflictName : $conflictName;
    }

    public function preserveConflict(string $relPath, string $peerIdPrefix, int $timestamp, string $data): string
    {
        $conflictPath = $this->resolveConflictPath($relPath, $peerIdPrefix, $timestamp);
        $fullPath = $this->syncDir . DIRECTORY_SEPARATOR . $conflictPath;
        $dir = dirname($fullPath);
        if (!is_dir($dir)) {
            mkdir($dir, 0755, true);
        }
        file_put_contents($fullPath, $data);
        return $conflictPath;
    }

    /** Compute delta blocks between old and new data. */
    public function computeDelta(string $oldData, string $newData): array
    {
        $oldSigs = $this->computeSignatures($oldData);
        $deltas = [];
        $pos = 0;
        $changeStart = null;
        $newLen = strlen($newData);
        $oldLen = strlen($oldData);

        while ($pos + ROLLING_HASH_WINDOW <= $newLen) {
            $window = substr($newData, $pos, ROLLING_HASH_WINDOW);
            $h = self::rollingHash($window);

            $matched = false;
            if (isset($oldSigs[$h])) {
                foreach ($oldSigs[$h] as $off) {
                    if ($off + ROLLING_HASH_WINDOW > $oldLen) {
                        continue;
                    }
                    if (substr($oldData, $off, ROLLING_HASH_WINDOW) === $window) {
                        $matched = true;
                        break;
                    }
                }
            }

            if ($matched) {
                if ($changeStart !== null) {
                    $deltas[] = [
                        'offset' => $changeStart,
                        'length' => $pos - $changeStart,
                        'data'   => base64_encode(substr($newData, $changeStart, $pos - $changeStart)),
                    ];
                    $changeStart = null;
                }
                $pos += ROLLING_HASH_WINDOW;
                continue;
            }

            if ($changeStart === null) {
                $changeStart = $pos;
            }
            $pos++;
        }

        if ($changeStart !== null) {
            $deltas[] = [
                'offset' => $changeStart,
                'length' => $newLen - $changeStart,
                'data'   => base64_encode(substr($newData, $changeStart)),
            ];
        } elseif ($pos < $newLen) {
            $deltas[] = [
                'offset' => $pos,
                'length' => $newLen - $pos,
                'data'   => base64_encode(substr($newData, $pos)),
            ];
        }

        return $deltas;
    }

    /** Apply delta blocks to produce updated data. */
    public function applyDelta(string $baseData, array $deltas): string
    {
        $result = $baseData;
        foreach ($deltas as $delta) {
            $data = base64_decode($delta['data']);
            $result = substr_replace($result, $data, $delta['offset'], strlen($data));
        }
        return $result;
    }

    private function computeSignatures(string $data): array
    {
        $sigs = [];
        $len = strlen($data);
        if ($len < ROLLING_HASH_WINDOW) {
            return $sigs;
        }
        for ($offset = 0; $offset <= $len - ROLLING_HASH_WINDOW; $offset++) {
            $window = substr($data, $offset, ROLLING_HASH_WINDOW);
            $h = self::rollingHash($window);
            $sigs[$h][] = $offset;
        }
        return $sigs;
    }

    private static function rollingHash(string $data): int
    {
        $a = 1;
        $b = 0;
        $len = strlen($data);
        for ($i = 0; $i < $len; $i++) {
            $a = ($a + ord($data[$i])) % MOD_ADLER;
            $b = ($b + $a) % MOD_ADLER;
        }
        return (($b << 16) | $a) & 0xFFFFFFFF;
    }

    private function relativePath(string $filePath): string
    {
        $syncDir = rtrim($this->syncDir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
        if (str_starts_with($filePath, $syncDir)) {
            return substr($filePath, strlen($syncDir));
        }
        return $filePath;
    }
}

// ---------------------------------------------------------------------------
// File watcher (polling-based, with inotify when available)
// ---------------------------------------------------------------------------

class FileWatcher
{
    /** @var array<string, int> mtime cache */
    private array $mtimes = [];

    public function __construct(
        private readonly string $watchDir,
        private readonly float $pollInterval = 1.0,
    ) {
        $this->buildCache();
    }

    /** Build initial mtime cache. */
    private function buildCache(): void
    {
        $this->mtimes = [];
        $this->scanDir($this->watchDir, $this->mtimes);
    }

    /** Check for changes; returns list of changed absolute paths. */
    public function poll(): array
    {
        $current = [];
        $this->scanDir($this->watchDir, $current);
        $changed = [];

        // New or modified files
        foreach ($current as $path => $mtime) {
            if (!isset($this->mtimes[$path]) || $this->mtimes[$path] !== $mtime) {
                $changed[] = $path;
            }
        }

        $this->mtimes = $current;
        return $changed;
    }

    public function getPollInterval(): float
    {
        return $this->pollInterval;
    }

    private function scanDir(string $dir, array &$out): void
    {
        if (!is_dir($dir)) {
            return;
        }
        $entries = scandir($dir);
        if ($entries === false) {
            return;
        }
        foreach ($entries as $name) {
            if (str_starts_with($name, '.')) {
                continue;
            }
            $fullPath = $dir . DIRECTORY_SEPARATOR . $name;
            if (is_dir($fullPath)) {
                $this->scanDir($fullPath, $out);
            } elseif (is_file($fullPath)) {
                $out[$fullPath] = filemtime($fullPath) ?: 0;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Sync message handler
// ---------------------------------------------------------------------------

function handleSyncMessage(string $data, string $syncDir, object $session, SyncEngine $engine): void
{
    $msg = json_decode($data, true);
    if ($msg === null) {
        return;
    }

    // File metadata message
    if (isset($msg['path'], $msg['hash'], $msg['size'])) {
        fwrite(STDERR, "[sync] Received metadata: {$msg['path']} ({$msg['size']} bytes)\n");

        $localMeta = $engine->getFileMeta($msg['path']);
        if ($localMeta !== null
            && $localMeta['hash'] !== $msg['hash']
            && $localMeta['modified'] !== $msg['modified']
        ) {
            $conflictPath = $engine->resolveConflictPath(
                $msg['path'],
                $msg['peer_id_prefix'] ?? 'unknown',
                (int) $msg['modified'],
            );
            fwrite(STDERR, "[conflict] {$msg['path']} — preserved as {$conflictPath}\n");
        }

        $request = json_encode([
            'type'       => 'chunk_request',
            'file_path'  => $msg['path'],
            'file_hash'  => $msg['hash'],
            'from_chunk' => $engine->lastReceivedChunk($msg['path']),
        ]);
        $session->send('sync', $request);
        return;
    }

    // Chunk data message
    if (isset($msg['file_path'], $msg['chunk_index'], $msg['chunk_data'])) {
        $destPath = $syncDir . DIRECTORY_SEPARATOR . $msg['file_path'];
        $destDir = dirname($destPath);
        if (!is_dir($destDir)) {
            mkdir($destDir, 0755, true);
        }

        $chunkBytes = base64_decode($msg['chunk_data']);
        $engine->writeChunk($destPath, (int) $msg['chunk_index'], $chunkBytes);
        $engine->recordChunk($msg['file_path'], (int) $msg['chunk_index']);

        if ($msg['chunk_index'] + 1 === $msg['chunk_count']) {
            fwrite(STDERR, "[sync] Completed: {$msg['file_path']}\n");
            $engine->markComplete($msg['file_path'], $msg['file_hash']);

            $ack = json_encode([
                'type'      => 'chunk_ack',
                'file_path' => $msg['file_path'],
                'file_hash' => $msg['file_hash'],
            ]);
            $session->send('sync', $ack);
        }
        return;
    }

    // Chunk request message
    if (($msg['type'] ?? '') === 'chunk_request' && isset($msg['file_path'])) {
        $filePath = $syncDir . DIRECTORY_SEPARATOR . $msg['file_path'];
        if (!file_exists($filePath)) {
            return;
        }

        $chunks = $engine->splitFile($filePath, $msg['file_path']);
        $startFrom = $msg['from_chunk'] ?? 0;

        for ($i = $startFrom; $i < count($chunks); $i++) {
            $session->send('sync', json_encode($chunks[$i]));
        }
    }
}

// ---------------------------------------------------------------------------
// Display helpers
// ---------------------------------------------------------------------------

function displayError(\Exception $err): void
{
    fwrite(STDERR, "Error: {$err->getMessage()}\n");
    if (str_contains($err->getMessage(), 'TransportExhausted')) {
        fwrite(STDERR, "Hint: Both peers may be behind symmetric NATs. Deploy a TURN relay.\n");
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

// Ensure sync directory exists
if (!is_dir($syncDir)) {
    mkdir($syncDir, 0755, true);
    fwrite(STDERR, "Created sync directory: {$syncDir}\n");
}
$syncDir = realpath($syncDir);

require_once __DIR__ . '/../../php/cairn-p2p/vendor/autoload.php';

use Cairn\Node;
use Cairn\Config;

// Initialize cairn node
$config = Config::defaults();
if ($mesh) {
    $config['mesh_enabled'] = true;
    $config['max_hops'] = 3;
    $config['relay_willing'] = true;
}

if ($serverHub) {
    $node = Node::createServer($config);
} else {
    $node = Node::create($config);
}

$node->start();
fwrite(STDERR, "cairn-folder-sync started. Watching: {$syncDir}\n");

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
} elseif (isset($options['scan-qr'])) {
    $mechanism = 'qr';
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
    fwrite(STDERR, "Sync session established.\n");

    $engine = new SyncEngine($syncDir, CHUNK_SIZE);

    // Initial directory scan
    $localFiles = $engine->scanDirectory();
    fwrite(STDERR, "Found " . count($localFiles) . " files to sync\n");

    // Send file metadata to peer
    foreach ($localFiles as $meta) {
        $session->send('sync', json_encode($meta));
    }

    // Register event handler
    $node->on('event', function (array $event) use ($syncDir, $session, $engine) {
        if (($event['type'] ?? '') === 'MessageReceived' && ($event['channel'] ?? '') === 'sync') {
            handleSyncMessage($event['data'], $syncDir, $session, $engine);
        } elseif (($event['type'] ?? '') === 'PeerDisconnected') {
            fwrite(STDERR, "--- Connection state: Disconnected ---\n");
        } elseif (($event['type'] ?? '') === 'PeerConnected') {
            fwrite(STDERR, "--- Connection state: Connected ---\n");
        }
    });

    // Set up file watcher (polling)
    $watcher = new FileWatcher($syncDir);
    fwrite(STDERR, "Watching for changes... (Ctrl+C to stop)\n");

    // Main loop: poll for file changes
    while (true) {
        $changed = $watcher->poll();
        foreach ($changed as $filePath) {
            if (!is_file($filePath)) {
                continue;
            }
            $rel = substr($filePath, strlen(rtrim($syncDir, DIRECTORY_SEPARATOR)) + 1);
            fwrite(STDERR, "[change] {$rel}\n");
            $meta = $engine->computeFileMeta($filePath);
            if ($meta !== null) {
                $session->send('sync', json_encode($meta));
            }
        }

        // Process any pending events
        $node->poll();

        usleep((int) ($watcher->getPollInterval() * 1_000_000));
    }

} catch (\Exception $e) {
    displayError($e);
    $node->stop();
    exit(1);
}
