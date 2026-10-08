#!/usr/bin/env python3
"""
adapter.py
Racebird's plugin-owned test adapter: encapsulates obfs4-specific config
generation (node-id/keypair/drbg-seed and the listener-to-connector link cert)
so the central scenario orchestrator (raceboat/test/integration/) never needs
to know racebird's parameter names or its cross-node cert-sharing requirement.
"""

import platform
import sys
from pathlib import Path

sys.path.insert(
    0, str(Path(__file__).resolve().parents[2] / "raceboat" / "test" / "integration")
)
from adapter_types import NodeContribution, NodeRequest  # noqa: E402

CHANNEL_NAME = "obfs4"
LINK_PORT = 8675

# A bootstrap scenario may use racebird for both the "initial" and "final"
# slots on the same node; each needs its own listening port so the two
# links don't collide. "channel" (plain client-connect) keeps the original
# port for backward compatibility.
SLOT_PORTS = {"channel": LINK_PORT, "initial": LINK_PORT, "final": LINK_PORT + 1}

# TODO(Further Considerations #1 in plan.md): static, known-good obfs4
# node-id/keypair/drbg-seed/cert fixture (matches the values previously
# hand-pasted into racebird/test/docker-compose.yml). Replace with a real
# per-run generator (a thin CLI around config-utils/Configs.go, or scraping a
# live plugin's /tmp/obfs4_bridgeline.txt) once available.
_FIXTURE = {
    "node-id": "95b31191f959d7608983df251a6cc8e9f898b4ff",
    "private-key": "aac12fdae5a19876392e33646fb12dda135e4c8f55e91050eccb1307053a2989",
    "drbg-seed": "ca709ead0fcc07efdf839539bab201eb8a80b7bf64884732",
    "iat-mode": "0",
    "cert": "lbMRkflZ12CJg98lGmzI6fiYtP9ycAfB5yIdTK1b6tsVLV3MLjJQQ+qz8zz4g/DUrp+KUQ",
}


def _detect_host_architecture() -> str:
    machine = platform.machine().lower()
    if machine in {"x86_64", "amd64"}:
        return "x86_64"
    if machine in {"arm64", "aarch64"}:
        return "arm64-v8a"
    raise ValueError(
        f"Unsupported host architecture for Docker builds: {platform.machine()}"
    )


def kit_dir(role: str) -> Path:
    # Both roles currently share the same built artifacts for this plugin
    # (role is accepted only to satisfy the adapter contract - see
    # adapter_types.py docstring).
    plugin_root = Path(__file__).resolve().parents[1]
    return (
        plugin_root
        / "kit"
        / "artifacts"
        / f"linux-{_detect_host_architecture()}-server"
        / "PluginRacebird"
    )


def generate_node_contribution(request: NodeRequest) -> NodeContribution:
    # racebird is a plain (non-composed) plugin, so --param entries are prefixed
    # with its plugin id (manifest.json plugins[].file_path), not a composition
    # id. If a scenario ever wraps racebird in a composition, honor that instead
    # (see adapter_types.NodeRequest.composition_name).
    prefix = request.composition_name or "PluginRacebird"
    contribution = NodeContribution(
        params={
            f"{prefix}.node-id": _FIXTURE["node-id"],
            f"{prefix}.private-key": _FIXTURE["private-key"],
            f"{prefix}.drbg-seed": _FIXTURE["drbg-seed"],
            f"{prefix}.iat-mode": _FIXTURE["iat-mode"],
            "hostname": request.ip,
        },
        channel_name=CHANNEL_NAME,
        kit_dir=kit_dir(request.role),
    )

    if request.role == "listener":
        port = SLOT_PORTS.get(request.slot, LINK_PORT)
        contribution.address_output = {
            "addr": f"{request.ip}:{port}",
            "cert": _FIXTURE["cert"],
            "iat": _FIXTURE["iat-mode"],
        }
    elif request.role == "connector":
        contribution.needs_peer_address = True
        listener_address = next(iter(request.peer_context.values()), None)
        if listener_address is None:
            raise ValueError(
                "racebird adapter: connector node requires a listener's "
                "address_output in peer_context, but none was provided"
            )
        contribution.cli_flags["send-address"] = (
            '{"addr":"%s","cert":"%s","iat":"%s"}'
            % (listener_address["addr"], listener_address["cert"], listener_address["iat"])
        )
    else:
        raise ValueError(f"racebird adapter: unknown role '{request.role}'")

    return contribution
