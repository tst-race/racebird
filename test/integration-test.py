#!/opt/homebrew/bin/python3
"""
integration-test.py
Racebird plugin integration test wrapper.
This script prepares plugin-specific artifacts and delegates to the
generic race-cli integration test framework in the raceboat repository.
"""

import os
import subprocess
import sys
from pathlib import Path
import shutil


def main():
    # Get script directory
    script_dir = Path(__file__).parent.resolve()
    raceboat_dir = script_dir / '..' / '..' / 'raceboat'
    raceboat_test_dir = raceboat_dir / 'test' / 'integration'
    
    # Validate raceboat test directory exists
    if not raceboat_test_dir.is_dir():
        print(f"Error: Cannot find raceboat test directory at: {raceboat_test_dir}")
        print("Expected directory structure:")
        print("  te-raceboat-things/")
        print("    raceboat/test/integration/")
        print("    racebird/scripts/")
        sys.exit(1)
    
    # Step 1: Setup plugin kits
    print("Setting up Racebird plugin kits...")
    setup_script = script_dir / 'setup.py'
    result = subprocess.run([sys.executable, str(setup_script)])
    if result.returncode != 0:
        print("Failed to setup plugin kits")
        sys.exit(1)
    
    # Step 2: Clear logs
    print("Clearing old logs...")
    server_logs = script_dir / 'server-logs'
    client_logs = script_dir / 'client-logs'
    
    for log_dir in [server_logs, client_logs]:
        if log_dir.exists():
            for item in log_dir.iterdir():
                try:
                    if item.is_file():
                        item.unlink()
                    elif item.is_dir():
                        shutil.rmtree(item)
                except Exception as e:
                    # Ignore errors during cleanup
                    pass
    
    # Step 3: Run generic integration test from raceboat
    print("Running integration test...")
    test_runner = raceboat_test_dir / 'run-integration-test.py'
    compose_file = script_dir / 'docker-compose.yml'
    
    # Execute the test runner
    os.execv(
        sys.executable,
        [
            sys.executable,
            str(test_runner),
            '--compose-file', str(compose_file),
            '--wait-time', '10',
            '--name', 'Racebird obfs4 Plugin'
        ]
    )


if __name__ == '__main__':
    main()
