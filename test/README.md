# Racebird Integration Testing

Racebird's integration test config now lives centrally under
`raceboat/test/integration/` (scenario JSON + generated docker-compose files),
not in this directory. This directory only holds `adapter.py`, racebird's
plugin-owned test config generator (obfs4 node-id/cert generation and its
cross-node cert-sharing requirement) - see `raceboat/test/integration/README.md`
and `adapter_types.py` for the adapter contract.

## Quick Start

```bash
cd ../../raceboat/test/integration

# Build the plugin and run its default scenario (racebird-client-connect)
python3 build-test.py --plugin-dir ../../racebird --rebuild-plugin

# Run a specific scenario directly (after building)
python3 run_scenario.py --scenario-id racebird-client-connect
```

## Files in this Directory

- **`adapter.py`** - Generates race-cli params/channel flags/kit path for
  racebird, given a node's role (listener/connector) in a scenario. Called by
  `raceboat/test/integration/generate_scenario.py`; never invoked directly.

## Scenarios

See `raceboat/test/integration/scenarios/racebird-client-connect.json` for the
current scenario definition (topology, IPs, mode). Generated compose files,
merged kits, and per-node logs are written to
`raceboat/test/integration/generated/<scenario-id>/` each run.

