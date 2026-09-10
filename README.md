# Racebird (Raceboat Plugin)

The Racebird plugin wraps the Lyrebird pluggable transport to enable use of Obfs4 with Raceboat.

## Building

Racebird uses a docker-based build to build the plugin:

```
./build_artifacts_in_docker_image.sh
```

## Testing

Racebird has an automated dockerized integration test that validates bidirectional message delivery through the raceboat channel.

### Automated Integration Test via Raceboat Repository

Use the build-test orchestrator from the raceboat repository:

```bash
# Navigate to raceboat/test/integration directory
# Test with existing builds (fastest)
python3 build-test.py --plugin-dir ../../racebird

# Rebuild plugin and test
python3 build-test.py --plugin-dir ../../racebird --rebuild-plugin

# Full rebuild (raceboat + plugin)
python3 build-test.py --plugin-dir ../../racebird --rebuild-all

# See all options
python3 build-test.py --help
```

The test automatically:
1. Copies plugin artifacts to test directories
2. Starts docker containers with raceboat in client and server modes
3. Sends test messages bidirectionally through the raceboat channel
4. Validates successful delivery and reports results

See `raceboat/test/integration/BUILD_TEST_GUIDE.md` for detailed documentation.
