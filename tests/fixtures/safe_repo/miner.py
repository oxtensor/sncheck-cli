"""A minimal, well-behaved miner with no risky patterns."""

import subprocess


def run(command: list[str]) -> int:
    # No shell=True; arguments passed as a list.
    return subprocess.run(command, check=False).returncode


def main() -> None:
    print("mining...")
    run(["echo", "ready"])


if __name__ == "__main__":
    main()
