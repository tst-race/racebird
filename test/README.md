# Racebird Integration Testing

This directory contains the integration test configuration for the Racebird plugin.

## Quick Start

Run the automated integration test using the build-test orchestrator from the raceboat repository:

```bash
# From this directory
cd ../../raceboat/test/integration

# Test with existing builds (fastest)
python3 build-test.py --plugin-dir ../../racebird

# Rebuild plugin and test (common during development)
python3 build-test.py --plugin-dir ../../racebird --rebuild-plugin

# Full rebuild (after pulling changes)
python3 build-test.py --plugin-dir ../../racebird --rebuild-all
```

## Files in this Directory

- **`setup.py`** - Copies built plugin artifacts to `kits/` directory for testing
- **`docker-compose.yml`** - Docker compose configuration for integration test
- **`kits/`** - Plugin artifacts directory (populated by setup.py)
- **`*-logs/`** - Log directories for test containers
- **`integration-test.py`** - Legacy wrapper script (use build-test.py instead)

## How It Works

1. The `build-test.py` orchestrator runs `setup.py` to copy plugin artifacts
2. Docker containers are started using `docker-compose.yml`
3. Test stubs validate bidirectional message delivery through raceboat
4. Results are reported with clear pass/fail status

## Test Configuration

The `docker-compose.yml` file configures:
- **rbserver** - raceboat in `--server-connect` mode
- **rbclient** - raceboat in `--client-connect` mode
- Network configuration for plugin communication
- Plugin-specific parameters (node-id, private-key, etc.)

## Detailed Documentation

See `raceboat/test/integration/BUILD_TEST_GUIDE.md` for:
- Complete usage examples
- Rebuild workflow options
- Troubleshooting guide
- CI/CD integration examples
