"""Configuration builder with tier presets (spec 11, section 1)."""

from __future__ import annotations

from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Default STUN servers
# ---------------------------------------------------------------------------

DEFAULT_STUN_SERVERS: list[str] = [
    "stun:stun.l.google.com:19302",
    "stun:stun1.l.google.com:19302",
    "stun:stun.cloudflare.com:3478",
]


# ---------------------------------------------------------------------------
# Supporting dataclasses
# ---------------------------------------------------------------------------


@dataclass
class TurnServer:
    """TURN relay server credentials."""

    url: str = ""
    username: str = ""
    credential: str = ""


@dataclass
class ReconnectionPolicy:
    """Reconnection and timeout policy (spec section 2.2)."""

    connect_timeout: float = 30.0
    transport_timeout: float = 10.0
    reconnect_max_duration: float = 3600.0
    reconnect_backoff_initial: float = 1.0
    reconnect_backoff_max: float = 60.0
    reconnect_backoff_factor: float = 2.0
    rendezvous_poll_interval: float = 30.0
    session_expiry: float = 86400.0
    pairing_payload_expiry: float = 300.0


@dataclass
class MeshSettings:
    """Mesh routing settings (spec section 1.2)."""

    mesh_enabled: bool = False
    max_hops: int = 3
    relay_willing: bool = False
    relay_capacity: int = 10


@dataclass
class PinFormat:
    """PIN code format configuration."""

    length: int = 8
    group_size: int = 4
    separator: str = "-"


# ---------------------------------------------------------------------------
# CairnConfig
# ---------------------------------------------------------------------------


@dataclass
class CairnConfig:
    """Top-level configuration (spec section 1.1).

    Every field has a sensible default, enabling zero-config usage (Tier 0).
    """

    stun_servers: list[str] = field(
        default_factory=lambda: list(DEFAULT_STUN_SERVERS)
    )
    turn_servers: list[TurnServer] = field(
        default_factory=list
    )
    signaling_servers: list[str] = field(
        default_factory=list
    )
    tracker_urls: list[str] = field(default_factory=list)
    bootstrap_nodes: list[str] = field(default_factory=list)
    reconnection_policy: ReconnectionPolicy = field(
        default_factory=ReconnectionPolicy
    )
    mesh_settings: MeshSettings = field(
        default_factory=MeshSettings
    )
    server_mode: bool = False
    app_identifier: str | None = None
    pin_format: "PinFormat" = field(default_factory=lambda: PinFormat())
    auto_approve_pairing: bool = False
    pairing_password: str | None = None
    pairing_message: str | None = None

    # --- Tier presets ---

    @classmethod
    def tier0(cls) -> CairnConfig:
        """Tier 0: fully decentralized, zero-config."""
        return cls()

    @classmethod
    def tier1(
        cls,
        signaling_servers: list[str] | None = None,
        turn_servers: list[TurnServer] | None = None,
    ) -> CairnConfig:
        """Tier 1: add signaling server and optional TURN relay."""
        return cls(
            signaling_servers=signaling_servers or [],
            turn_servers=turn_servers or [],
        )

    @classmethod
    def tier2(
        cls,
        signaling_servers: list[str] | None = None,
        turn_servers: list[TurnServer] | None = None,
        tracker_urls: list[str] | None = None,
        bootstrap_nodes: list[str] | None = None,
    ) -> CairnConfig:
        """Tier 2: self-hosted infrastructure."""
        return cls(
            signaling_servers=signaling_servers or [],
            turn_servers=turn_servers or [],
            tracker_urls=tracker_urls or [],
            bootstrap_nodes=bootstrap_nodes or [],
        )

    @classmethod
    def tier3(
        cls,
        signaling_servers: list[str] | None = None,
        turn_servers: list[TurnServer] | None = None,
        tracker_urls: list[str] | None = None,
        bootstrap_nodes: list[str] | None = None,
        mesh_settings: MeshSettings | None = None,
    ) -> CairnConfig:
        """Tier 3: fully self-hosted with mesh routing."""
        return cls(
            signaling_servers=signaling_servers or [],
            turn_servers=turn_servers or [],
            tracker_urls=tracker_urls or [],
            bootstrap_nodes=bootstrap_nodes or [],
            mesh_settings=mesh_settings or MeshSettings(
                mesh_enabled=True
            ),
        )

    @classmethod
    def default_server(cls) -> CairnConfig:
        """Default server-mode config."""
        return cls(
            server_mode=True,
            reconnection_policy=ReconnectionPolicy(
                session_expiry=7 * 86400.0,
            ),
            mesh_settings=MeshSettings(
                relay_willing=True,
            ),
        )

    def validate(self) -> None:
        """Validate configuration. Raises ValueError on invalid settings."""
        if not self.stun_servers and not self.turn_servers:
            raise ValueError(
                "stun_servers must not be empty unless "
                "turn_servers are configured"
            )

        if self.reconnection_policy.reconnect_backoff_factor <= 1.0:
            raise ValueError(
                "reconnect_backoff_factor must be greater than 1.0"
            )

        if (
            self.mesh_settings.max_hops < 1
            or self.mesh_settings.max_hops > 10
        ):
            raise ValueError(
                "max_hops must be between 1 and 10"
            )
