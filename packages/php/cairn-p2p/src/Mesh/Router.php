<?php

declare(strict_types=1);

namespace Cairn\Mesh;

use Cairn\Crypto\PeerId;
use Cairn\Error\CairnException;

/**
 * Mesh networking configuration (spec 9.4).
 *
 * Mesh is opt-in and disabled by default. Server-mode peers override defaults
 * with meshEnabled=true, relayWilling=true, relayCapacity=100+.
 *
 * Matches packages/rs/cairn-p2p/src/mesh/mod.rs MeshConfig.
 */
final class MeshConfig
{
    public function __construct(
        /** Enable/disable mesh routing. Default: false. */
        public readonly bool $meshEnabled = false,
        /** Maximum relay hops allowed for any route. Default: 3. */
        public readonly int $maxHops = 3,
        /** Whether this peer is willing to relay traffic for others. Default: false. */
        public readonly bool $relayWilling = false,
        /** Maximum simultaneous relay connections this peer will serve. Default: 10. */
        public readonly int $relayCapacity = 10,
    ) {
    }

    /**
     * Configuration preset for server-mode peers.
     */
    public static function serverMode(): self
    {
        return new self(
            meshEnabled: true,
            maxHops: 3,
            relayWilling: true,
            relayCapacity: 100,
        );
    }
}

/**
 * Errors specific to mesh networking operations.
 */
final class MeshException extends CairnException
{
    public static function meshDisabled(): self
    {
        return new self('mesh routing disabled');
    }

    public static function noRoute(string $destination): self
    {
        return new self("no route to peer {$destination}");
    }

    public static function maxHopsExceeded(int $got, int $max): self
    {
        return new self("max hops exceeded: {$got} > {$max}");
    }

    public static function relayCapacityFull(int $active, int $capacity): self
    {
        return new self("relay capacity full ({$active}/{$capacity})");
    }

    public static function relayNotWilling(): self
    {
        return new self('relay not willing');
    }

    public static function relayConnectionFailed(string $reason): self
    {
        return new self("relay connection failed: {$reason}");
    }
}

/**
 * A route to a destination peer, potentially through intermediate relay hops.
 *
 * Matches packages/rs/cairn-p2p/src/mesh/routing.rs Route.
 */
final class Route
{
    /**
     * @param list<PeerId> $hops Ordered intermediate relay peer IDs (empty = direct)
     * @param int $latencyMs Measured or estimated latency in milliseconds
     * @param int $bandwidthBps Estimated available bandwidth in bytes/sec
     * @param float $lastSeen When this route was last confirmed reachable (microtime)
     */
    public function __construct(
        public readonly array $hops,
        public readonly int $latencyMs,
        public readonly int $bandwidthBps,
        public readonly float $lastSeen,
    ) {
    }

    /**
     * Create a direct route (zero hops).
     */
    public static function direct(int $latencyMs, int $bandwidthBps): self
    {
        return new self(
            hops: [],
            latencyMs: $latencyMs,
            bandwidthBps: $bandwidthBps,
            lastSeen: microtime(true),
        );
    }

    /**
     * Create a relayed route through intermediate hops.
     *
     * @param list<PeerId> $hops
     */
    public static function relayed(array $hops, int $latencyMs, int $bandwidthBps): self
    {
        return new self(
            hops: $hops,
            latencyMs: $latencyMs,
            bandwidthBps: $bandwidthBps,
            lastSeen: microtime(true),
        );
    }

    /**
     * Number of hops (0 = direct).
     */
    public function hopCount(): int
    {
        return count($this->hops);
    }

    /**
     * Route selection key for comparison.
     *
     * Priority: hop_count ASC, latency_ms ASC, bandwidth_bps DESC.
     * Returns [hopCount, latencyMs, -bandwidthBps] so that sorting ascending
     * yields the best route first.
     *
     * @return array{int, int, int}
     */
    public function selectionKey(): array
    {
        return [$this->hopCount(), $this->latencyMs, -$this->bandwidthBps];
    }
}

/**
 * Routing table maintaining known peers and their reachability.
 *
 * Matches packages/rs/cairn-p2p/src/mesh/routing.rs RoutingTable.
 */
final class RoutingTable
{
    /** @var array<string, list<Route>> Map: destination peer ID string -> routes */
    private array $routes = [];

    public function __construct(
        private readonly int $maxHops,
    ) {
    }

    /**
     * Add or update a route to a destination peer.
     *
     * Routes exceeding maxHops are rejected.
     *
     * @throws MeshException
     */
    public function addRoute(PeerId $destination, Route $route): void
    {
        $hopCount = $route->hopCount();
        if ($hopCount > $this->maxHops) {
            throw MeshException::maxHopsExceeded($hopCount, $this->maxHops);
        }

        $key = (string) $destination;
        if (!isset($this->routes[$key])) {
            $this->routes[$key] = [];
        }
        $this->routes[$key][] = $route;
    }

    /**
     * Select the best route to a destination peer.
     *
     * Priority order per spec 9.2:
     * 1. Shortest hop count
     * 2. Lowest latency
     * 3. Highest bandwidth
     *
     * @throws MeshException
     */
    public function selectBestRoute(PeerId $destination): Route
    {
        $key = (string) $destination;
        $routes = $this->routes[$key] ?? null;

        if ($routes === null || $routes === []) {
            throw MeshException::noRoute($key);
        }

        $best = $routes[0];
        $bestKey = $best->selectionKey();

        for ($i = 1, $count = count($routes); $i < $count; $i++) {
            $candidateKey = $routes[$i]->selectionKey();
            if ($candidateKey < $bestKey) {
                $best = $routes[$i];
                $bestKey = $candidateKey;
            }
        }

        return $best;
    }

    /**
     * Get all known routes to a destination peer.
     *
     * @return list<Route>|null
     */
    public function getRoutes(PeerId $destination): ?array
    {
        $key = (string) $destination;
        return $this->routes[$key] ?? null;
    }

    /**
     * Remove all routes to a destination peer.
     */
    public function removeRoutes(PeerId $destination): void
    {
        $key = (string) $destination;
        unset($this->routes[$key]);
    }

    /**
     * Remove stale routes older than the given max age (in seconds).
     */
    public function expireRoutes(float $maxAge): void
    {
        $now = microtime(true);
        foreach ($this->routes as $key => $routes) {
            $this->routes[$key] = array_values(array_filter(
                $routes,
                fn(Route $r) => ($now - $r->lastSeen) < $maxAge,
            ));
            if ($this->routes[$key] === []) {
                unset($this->routes[$key]);
            }
        }
    }

    /**
     * Get the number of known destination peers.
     */
    public function peerCount(): int
    {
        return count($this->routes);
    }

    /**
     * Get the total number of routes across all destinations.
     */
    public function routeCount(): int
    {
        $total = 0;
        foreach ($this->routes as $routes) {
            $total += count($routes);
        }
        return $total;
    }

    /**
     * Get the max hops limit.
     */
    public function maxHops(): int
    {
        return $this->maxHops;
    }

    /**
     * Get all known destination peer ID strings.
     *
     * @return list<string>
     */
    public function destinations(): array
    {
        return array_keys($this->routes);
    }

    /**
     * Apply a topology update from a neighboring peer.
     *
     * Merges the neighbor's reachability information into the local routing table,
     * adding the neighbor as an additional hop to each advertised destination.
     */
    public function applyTopologyUpdate(PeerId $neighbor, MeshTopologyUpdate $update): int
    {
        $added = 0;
        foreach ($update->reachablePeers as $entry) {
            $hops = array_merge([$neighbor], $entry->viaHops);
            $route = new Route(
                hops: $hops,
                latencyMs: $entry->latencyMs,
                bandwidthBps: $entry->bandwidthBps,
                lastSeen: microtime(true),
            );

            try {
                $this->addRoute($entry->peerId, $route);
                $added++;
            } catch (MeshException) {
                // Route exceeds max hops, skip it
            }
        }
        return $added;
    }
}

/**
 * A topology update message exchanged between mesh peers (distance-vector).
 *
 * Contains the sender's known reachability: which peers it can reach and via which paths.
 *
 * Matches packages/rs/cairn-p2p/src/mesh/routing.rs MeshTopologyUpdate.
 */
final class MeshTopologyUpdate
{
    /**
     * @param list<ReachabilityEntry> $reachablePeers Peers reachable from the sender
     */
    public function __construct(
        public readonly array $reachablePeers,
    ) {
    }
}

/**
 * A single reachability entry in a topology update.
 *
 * Matches packages/rs/cairn-p2p/src/mesh/routing.rs ReachabilityEntry.
 */
final class ReachabilityEntry
{
    /**
     * @param PeerId $peerId The reachable peer
     * @param list<PeerId> $viaHops Intermediate hops (empty = direct from sender)
     * @param int $latencyMs Estimated latency in milliseconds
     * @param int $bandwidthBps Estimated bandwidth in bytes/sec
     */
    public function __construct(
        public readonly PeerId $peerId,
        public readonly array $viaHops,
        public readonly int $latencyMs,
        public readonly int $bandwidthBps,
    ) {
    }
}
