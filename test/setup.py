#!/usr/bin/env python3
"""
setup.py
Copies Racebird plugin kits from build artifacts to the scripts/kits directory
for integration testing.
"""

import shutil
import sys
from pathlib import Path


def main():
    script_dir = Path(__file__).parent.resolve()
    
    # Source and destination paths
    source = script_dir / '..' / 'kit' / 'artifacts' / 'linux-arm64-v8a-server' / 'PluginRacebird'
    dest = script_dir / 'kits' / 'PluginRacebird'
    
    # Ensure source exists
    if not source.exists():
        print(f"Error: Source plugin artifacts not found at: {source}")
        print("Make sure you have built the plugin first.")
        sys.exit(1)
    
    # Remove existing destination if it exists
    if dest.exists():
        shutil.rmtree(dest)
    
    # Ensure parent directory exists
    dest.parent.mkdir(parents=True, exist_ok=True)
    
    # Copy the plugin artifacts
    try:
        shutil.copytree(source, dest)
        print(f"Successfully copied plugin artifacts to {dest}")
        return 0
    except Exception as e:
        print(f"Error copying plugin artifacts: {e}")
        sys.exit(1)


if __name__ == '__main__':
    sys.exit(main())
