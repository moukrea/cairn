<?php

declare(strict_types=1);

namespace Cairn\Transport;

use Cairn\Error\CairnException;
use React\Dns\Resolver\ResolverInterface;
use React\EventLoop\LoopInterface;
use React\Promise\Deferred;
use React\Promise\PromiseInterface;

use function React\Promise\resolve;
use function React\Promise\reject;

/**
 * Detected NAT type, exposed as a read-only diagnostic.
 *
 * Application behavior should NEVER depend on NAT type -- the transport
 * chain handles it transparently. This diagnostic is provided for
 * debugging connectivity issues only.
 *
 * Matches packages/rs/cairn-p2p/src/transport/nat.rs.
 */
enum NatType: string
{
    /** Host has a public IP, no NAT. */
    case Open = 'open';
    /** Any external host can send to the mapped port (full cone / EIM+EIF). */
    case FullCone = 'full_cone';
    /** Only hosts the internal host has sent to can reply (address-restricted). */
    case RestrictedCone = 'restricted_cone';
    /** Restricted by both IP and port. */
    case PortRestrictedCone = 'port_restricted_cone';
    /** Different mapping per destination -- hole punching unlikely. */
    case Symmetric = 'symmetric';
    /** Detection failed or not yet attempted. */
    case Unknown = 'unknown';
}

/**
 * Read-only network diagnostic info.
 */
final class NetworkInfo
{
    public function __construct(
        public readonly NatType $natType = NatType::Unknown,
        public readonly ?string $externalAddr = null,
    ) {
    }
}

/**
 * STUN magic cookie (RFC 5389 section 6).
 */
const STUN_MAGIC_COOKIE = 0x2112A442;

/**
 * STUN message type: Binding Request.
 */
const STUN_BINDING_REQUEST = 0x0001;

/**
 * STUN message type: Binding Response (success).
 */
const STUN_BINDING_RESPONSE = 0x0101;

/**
 * STUN attribute types.
 */
const ATTR_MAPPED_ADDRESS = 0x0001;
const ATTR_XOR_MAPPED_ADDRESS = 0x0020;

/**
 * Default public STUN servers.
 */
const DEFAULT_STUN_SERVERS = [
    'stun.l.google.com:19302',
    'stun1.l.google.com:19302',
];

/**
 * STUN-based NAT type detector.
 *
 * Queries configured STUN servers and classifies the NAT type by
 * comparing mapped addresses across servers (simplified RFC 5780 logic).
 *
 * Supports both synchronous detection (detect()) and fully async
 * detection via ReactPHP event loop (detectAsync()).
 *
 * Matches packages/rs/cairn-p2p/src/transport/nat.rs.
 */
final class NatDetector
{
    /** @var list<string> */
    private array $stunServers;
    private float $timeout;
    private ?LoopInterface $loop;
    private ?ResolverInterface $dnsResolver;

    /**
     * @param list<string> $stunServers STUN server addresses (host:port)
     * @param float $timeout Per-request timeout in seconds
     * @param LoopInterface|null $loop ReactPHP event loop for async operations
     * @param ResolverInterface|null $dnsResolver ReactPHP DNS resolver for async DNS
     */
    public function __construct(
        array $stunServers = DEFAULT_STUN_SERVERS,
        float $timeout = 3.0,
        ?LoopInterface $loop = null,
        ?ResolverInterface $dnsResolver = null,
    ) {
        $this->stunServers = $stunServers;
        $this->timeout = $timeout;
        $this->loop = $loop;
        $this->dnsResolver = $dnsResolver;
    }

    /**
     * Detect the NAT type by querying STUN servers (synchronous fallback).
     *
     * Returns NetworkInfo with NatType::Unknown if detection fails.
     * Never throws -- failures result in Unknown.
     *
     * @deprecated Use detectAsync() with a ReactPHP event loop for non-blocking operation.
     */
    public function detect(): NetworkInfo
    {
        if (empty($this->stunServers)) {
            return new NetworkInfo();
        }

        /** @var list<array{server: string, ip: string, port: int}> $mappedAddrs */
        $mappedAddrs = [];

        foreach ($this->stunServers as $server) {
            $mapped = $this->stunBindingRequestSync($server);
            if ($mapped !== null) {
                $mappedAddrs[] = [
                    'server' => $server,
                    'ip' => $mapped['ip'],
                    'port' => $mapped['port'],
                ];
            }
        }

        if (empty($mappedAddrs)) {
            return new NetworkInfo();
        }

        $externalAddr = $mappedAddrs[0]['ip'] . ':' . $mappedAddrs[0]['port'];
        $natType = self::classifyNat($mappedAddrs);

        return new NetworkInfo($natType, $externalAddr);
    }

    /**
     * Detect the NAT type asynchronously using ReactPHP event loop.
     *
     * Uses async DNS resolution (react/dns) and non-blocking UDP for
     * STUN queries. Never blocks the event loop.
     *
     * @return PromiseInterface<NetworkInfo>
     */
    public function detectAsync(): PromiseInterface
    {
        if (empty($this->stunServers)) {
            return resolve(new NetworkInfo());
        }

        if ($this->loop === null) {
            return reject(new CairnException('NatDetector requires a LoopInterface for async detection'));
        }

        $promises = [];
        foreach ($this->stunServers as $server) {
            $promises[$server] = $this->stunBindingRequestAsync($server);
        }

        // Collect all results (resolve even if individual queries fail)
        $deferred = new Deferred();
        $results = [];
        $remaining = count($promises);

        foreach ($promises as $server => $promise) {
            $promise->then(
                function (?array $mapped) use ($server, &$results, &$remaining, $deferred): void {
                    if ($mapped !== null) {
                        $results[] = [
                            'server' => $server,
                            'ip' => $mapped['ip'],
                            'port' => $mapped['port'],
                        ];
                    }
                    if (--$remaining === 0) {
                        $deferred->resolve($results);
                    }
                },
                function () use (&$remaining, $deferred, &$results): void {
                    if (--$remaining === 0) {
                        $deferred->resolve($results);
                    }
                },
            );
        }

        return $deferred->promise()->then(function (array $mappedAddrs): NetworkInfo {
            if (empty($mappedAddrs)) {
                return new NetworkInfo();
            }

            $externalAddr = $mappedAddrs[0]['ip'] . ':' . $mappedAddrs[0]['port'];
            $natType = self::classifyNat($mappedAddrs);

            return new NetworkInfo($natType, $externalAddr);
        });
    }

    /**
     * Build a minimal STUN Binding Request (20 bytes header, no attributes).
     */
    public static function buildBindingRequest(string $transactionId): string
    {
        $buf = '';
        // Type: Binding Request (0x0001)
        $buf .= pack('n', STUN_BINDING_REQUEST);
        // Message Length: 0
        $buf .= pack('n', 0);
        // Magic Cookie
        $buf .= pack('N', STUN_MAGIC_COOKIE);
        // Transaction ID (12 bytes)
        $buf .= $transactionId;

        return $buf;
    }

    /**
     * Parse a STUN Binding Response.
     *
     * @return array{ip: string, port: int}|null
     * @throws CairnException
     */
    public static function parseBindingResponse(string $data, string $expectedTxnId): ?array
    {
        if (strlen($data) < 20) {
            throw new CairnException('STUN response too short');
        }

        /** @var array{1: int} $unpackedType */
        $unpackedType = unpack('n', substr($data, 0, 2));
        $msgType = $unpackedType[1];
        if ($msgType !== STUN_BINDING_RESPONSE) {
            throw new CairnException(sprintf(
                'unexpected STUN message type: 0x%04x',
                $msgType,
            ));
        }

        /** @var array{1: int} $unpackedLen */
        $unpackedLen = unpack('n', substr($data, 2, 2));
        $msgLen = $unpackedLen[1];

        /** @var array{1: int} $unpackedMagic */
        $unpackedMagic = unpack('N', substr($data, 4, 4));
        $magic = $unpackedMagic[1];
        if ($magic !== STUN_MAGIC_COOKIE) {
            throw new CairnException('invalid STUN magic cookie');
        }

        $txnId = substr($data, 8, 12);
        if ($txnId !== $expectedTxnId) {
            throw new CairnException('STUN transaction ID mismatch');
        }

        // Parse attributes
        $attrEnd = min(20 + $msgLen, strlen($data));
        $offset = 20;
        $xorMapped = null;
        $mapped = null;

        while ($offset + 4 <= $attrEnd) {
            /** @var array{1: int, 2: int} $attrHeader */
            $attrHeader = unpack('n2', substr($data, $offset, 4));
            $attrType = $attrHeader[1];
            $attrLen = $attrHeader[2];
            $attrStart = $offset + 4;

            if ($attrStart + $attrLen > $attrEnd) {
                break;
            }

            $attrData = substr($data, $attrStart, $attrLen);

            if ($attrType === ATTR_XOR_MAPPED_ADDRESS) {
                $xorMapped = self::parseXorMappedAddress($attrData, $expectedTxnId);
            } elseif ($attrType === ATTR_MAPPED_ADDRESS) {
                $mapped = self::parseMappedAddress($attrData);
            }

            // Attributes are padded to 4-byte boundaries
            $paddedLen = ($attrLen + 3) & ~3;
            $offset = $attrStart + $paddedLen;
        }

        return $xorMapped ?? $mapped;
    }

    /**
     * Parse XOR-MAPPED-ADDRESS attribute (RFC 5389 section 15.2).
     *
     * @return array{ip: string, port: int}|null
     */
    private static function parseXorMappedAddress(string $data, string $txnId): ?array
    {
        if (strlen($data) < 8) {
            return null;
        }

        $family = ord($data[1]);
        /** @var array{1: int} $portUnpacked */
        $portUnpacked = unpack('n', substr($data, 2, 2));
        $xorPort = $portUnpacked[1] ^ (STUN_MAGIC_COOKIE >> 16);

        if ($family === 0x01) {
            // IPv4
            /** @var array{1: int} $ipUnpacked */
            $ipUnpacked = unpack('N', substr($data, 4, 4));
            $xorIp = $ipUnpacked[1] ^ STUN_MAGIC_COOKIE;
            $ip = long2ip($xorIp);
            if ($ip === false) {
                return null;
            }
            return ['ip' => $ip, 'port' => $xorPort];
        }

        if ($family === 0x02) {
            // IPv6
            if (strlen($data) < 20) {
                return null;
            }
            $ipBytes = substr($data, 4, 16);
            // XOR with magic cookie (4 bytes) + transaction ID (12 bytes)
            $xorKey = pack('N', STUN_MAGIC_COOKIE) . $txnId;
            $result = '';
            for ($i = 0; $i < 16; $i++) {
                $result .= chr(ord($ipBytes[$i]) ^ ord($xorKey[$i]));
            }
            $ip = inet_ntop($result);
            if ($ip === false) {
                return null;
            }
            return ['ip' => $ip, 'port' => $xorPort];
        }

        return null;
    }

    /**
     * Parse MAPPED-ADDRESS attribute (RFC 5389 section 15.1).
     *
     * @return array{ip: string, port: int}|null
     */
    private static function parseMappedAddress(string $data): ?array
    {
        if (strlen($data) < 8) {
            return null;
        }

        $family = ord($data[1]);
        /** @var array{1: int} $portUnpacked */
        $portUnpacked = unpack('n', substr($data, 2, 2));
        $port = $portUnpacked[1];

        if ($family === 0x01) {
            $ip = sprintf('%d.%d.%d.%d', ord($data[4]), ord($data[5]), ord($data[6]), ord($data[7]));
            return ['ip' => $ip, 'port' => $port];
        }

        if ($family === 0x02) {
            if (strlen($data) < 20) {
                return null;
            }
            $ipBytes = substr($data, 4, 16);
            $ip = inet_ntop($ipBytes);
            if ($ip === false) {
                return null;
            }
            return ['ip' => $ip, 'port' => $port];
        }

        return null;
    }

    /**
     * Send a STUN Binding Request asynchronously using ReactPHP.
     *
     * Uses async DNS resolution and non-blocking UDP I/O via the event loop.
     *
     * @return PromiseInterface<array{ip: string, port: int}|null>
     */
    private function stunBindingRequestAsync(string $server): PromiseInterface
    {
        $parts = explode(':', $server);
        if (count($parts) !== 2) {
            return resolve(null);
        }
        $host = $parts[0];
        $port = (int) $parts[1];
        $loop = $this->loop;
        $timeout = $this->timeout;

        // Use async DNS resolver if available, otherwise fall back to resolve()
        $resolvePromise = $this->dnsResolver !== null
            ? $this->dnsResolver->resolve($host)
            : resolve($host);

        return $resolvePromise->then(
            function (string $resolvedIp) use ($port, $loop, $timeout): PromiseInterface {
                $deferred = new Deferred();

                // Create a non-blocking UDP socket via PHP streams
                $socket = @stream_socket_client(
                    "udp://{$resolvedIp}:{$port}",
                    $errno,
                    $errstr,
                    0,
                    STREAM_CLIENT_CONNECT,
                );

                if ($socket === false) {
                    $deferred->resolve(null);
                    return $deferred->promise();
                }

                stream_set_blocking($socket, false);

                $txnId = random_bytes(12);
                $request = self::buildBindingRequest($txnId);

                // Write the request
                $written = @fwrite($socket, $request);
                if ($written === false) {
                    @fclose($socket);
                    $deferred->resolve(null);
                    return $deferred->promise();
                }

                // Set up a read handler on the event loop
                $timeoutTimer = null;

                $timeoutTimer = $loop->addTimer($timeout, function () use ($socket, $loop, $deferred): void {
                    $loop->removeReadStream($socket);
                    @fclose($socket);
                    $deferred->resolve(null);
                });

                $loop->addReadStream($socket, function ($socket) use ($loop, $deferred, $txnId, $timeoutTimer): void {
                    $loop->removeReadStream($socket);
                    if ($timeoutTimer !== null) {
                        $loop->cancelTimer($timeoutTimer);
                    }

                    $buf = @fread($socket, 576);
                    @fclose($socket);

                    if ($buf === false || strlen($buf) < 20) {
                        $deferred->resolve(null);
                        return;
                    }

                    try {
                        $result = self::parseBindingResponse($buf, $txnId);
                        $deferred->resolve($result);
                    } catch (\Throwable) {
                        $deferred->resolve(null);
                    }
                });

                return $deferred->promise();
            },
            function () {
                // DNS resolution failed
                return null;
            },
        );
    }

    /**
     * Send a STUN Binding Request synchronously (blocking fallback).
     *
     * @return array{ip: string, port: int}|null
     */
    private function stunBindingRequestSync(string $server): ?array
    {
        // Parse server address
        $parts = explode(':', $server);
        if (count($parts) !== 2) {
            return null;
        }
        $host = $parts[0];
        $port = (int) $parts[1];

        // Resolve hostname
        $addrs = gethostbynamel($host);
        if ($addrs === false || empty($addrs)) {
            return null;
        }
        $resolvedIp = $addrs[0];

        // Create UDP socket
        $socket = @socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
        if ($socket === false) {
            return null;
        }

        try {
            // Set timeout
            $tv = [
                'sec' => (int) $this->timeout,
                'usec' => (int) (($this->timeout - floor($this->timeout)) * 1_000_000),
            ];
            socket_set_option($socket, SOL_SOCKET, SO_RCVTIMEO, $tv);
            socket_set_option($socket, SOL_SOCKET, SO_SNDTIMEO, $tv);

            // Generate transaction ID
            $txnId = random_bytes(12);

            // Build and send request
            $request = self::buildBindingRequest($txnId);
            $sent = @socket_sendto($socket, $request, strlen($request), 0, $resolvedIp, $port);
            if ($sent === false) {
                return null;
            }

            // Receive response
            $buf = '';
            $fromAddr = '';
            $fromPort = 0;
            $received = @socket_recvfrom($socket, $buf, 576, 0, $fromAddr, $fromPort);
            if ($received === false || $received < 20) {
                return null;
            }

            return self::parseBindingResponse($buf, $txnId);
        } catch (\Throwable) {
            return null;
        } finally {
            socket_close($socket);
        }
    }

    /**
     * Classify NAT type by comparing mapped addresses from multiple servers.
     *
     * @param list<array{server: string, ip: string, port: int}> $mappedAddrs
     */
    private static function classifyNat(array $mappedAddrs): NatType
    {
        if (empty($mappedAddrs)) {
            return NatType::Unknown;
        }

        if (count($mappedAddrs) < 2) {
            return NatType::Unknown;
        }

        $firstIp = $mappedAddrs[0]['ip'];
        $firstPort = $mappedAddrs[0]['port'];

        $allSameIp = true;
        $allSamePort = true;

        foreach ($mappedAddrs as $entry) {
            if ($entry['ip'] !== $firstIp) {
                $allSameIp = false;
            }
            if ($entry['port'] !== $firstPort) {
                $allSamePort = false;
            }
        }

        if (!$allSameIp) {
            return NatType::Symmetric;
        }

        if (!$allSamePort) {
            return NatType::Symmetric;
        }

        // Same IP and port from all servers -- some form of cone NAT.
        // Conservative: default to PortRestrictedCone without CHANGE-REQUEST.
        return NatType::PortRestrictedCone;
    }
}
