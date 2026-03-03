<?php

declare(strict_types=1);

namespace Cairn\Transport;

use Cairn\Error\CairnException;
use React\Dns\Resolver\ResolverInterface;
use React\EventLoop\LoopInterface;
use React\Promise\PromiseInterface;
use React\Socket\ConnectionInterface as ReactConnectionInterface;
use React\Socket\Connector;
use React\Socket\TcpServer;

use function React\Promise\reject;
use function React\Promise\resolve;

/**
 * TCP transport implementation using ReactPHP.
 *
 * Outbound connections via React\Socket\Connector with async DNS resolution.
 * Inbound listening via React\Socket\TcpServer.
 *
 * Priority 3 in the cairn transport fallback chain.
 */
final class TcpTransport implements TransportInterface
{
    private LoopInterface $loop;
    private ?ResolverInterface $dnsResolver;
    private ?TcpServer $server;
    private bool $active;

    public function __construct(LoopInterface $loop, ?ResolverInterface $dnsResolver = null)
    {
        $this->loop = $loop;
        $this->dnsResolver = $dnsResolver;
        $this->server = null;
        $this->active = false;
    }

    public function connect(string $address, float $timeout = 10.0): PromiseInterface
    {
        $options = [
            'timeout' => $timeout,
            'tls' => false,
            'unix' => false,
        ];

        if ($this->dnsResolver !== null) {
            $options['dns'] = $this->dnsResolver;
        }

        $connector = new Connector($options, $this->loop);

        return $connector->connect('tcp://' . $address)->then(
            function (ReactConnectionInterface $conn): TcpConnection {
                $this->active = true;
                return new TcpConnection($conn);
            },
            function (\Throwable $e): never {
                throw new CairnException('TCP connect failed: ' . $e->getMessage(), 0, $e);
            },
        );
    }

    public function listen(string $address, callable $onConnection): void
    {
        $this->server = new TcpServer($address, $this->loop);
        $this->active = true;

        $this->server->on('connection', function (ReactConnectionInterface $conn) use ($onConnection): void {
            $onConnection(new TcpConnection($conn));
        });

        $this->server->on('error', function (\Throwable $e): void {
            // Log or handle server errors
        });
    }

    public function close(): PromiseInterface
    {
        $this->active = false;
        if ($this->server !== null) {
            $this->server->close();
            $this->server = null;
        }
        return resolve(null);
    }

    public function type(): TransportType
    {
        return TransportType::Tcp;
    }

    public function isActive(): bool
    {
        return $this->active;
    }
}

/**
 * A single TCP connection wrapping a ReactPHP connection.
 */
final class TcpConnection implements ConnectionInterface
{
    private ReactConnectionInterface $conn;
    /** @var list<callable(string): void> */
    private array $dataCallbacks = [];
    /** @var list<callable(): void> */
    private array $closeCallbacks = [];

    public function __construct(ReactConnectionInterface $conn)
    {
        $this->conn = $conn;

        $this->conn->on('data', function (string $data): void {
            foreach ($this->dataCallbacks as $cb) {
                $cb($data);
            }
        });

        $this->conn->on('close', function (): void {
            foreach ($this->closeCallbacks as $cb) {
                $cb();
            }
        });
    }

    public function send(string $data): PromiseInterface
    {
        if (!$this->conn->isWritable()) {
            return reject(new CairnException('TCP connection is not writable'));
        }

        $this->conn->write($data);
        return resolve(null);
    }

    public function onData(callable $onData): void
    {
        $this->dataCallbacks[] = $onData;
    }

    public function onClose(callable $onClose): void
    {
        $this->closeCallbacks[] = $onClose;
    }

    public function close(): PromiseInterface
    {
        $this->conn->close();
        return resolve(null);
    }

    public function remoteAddress(): string
    {
        return $this->conn->getRemoteAddress() ?? '';
    }

    public function localAddress(): string
    {
        return $this->conn->getLocalAddress() ?? '';
    }
}
