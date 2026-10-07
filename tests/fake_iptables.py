"""Isolated iptables model used by the network-control regression tests."""

import json
import sys
from pathlib import Path


def main():
    state_file, family, *args = sys.argv[1:]
    state_path = Path(state_file)
    state = json.loads(state_path.read_text())
    table = "filter"
    while args and args[0].startswith("-"):
        if args[0] == "-w":
            args = args[2:]
        elif args[0] == "-t":
            table, args = args[1], args[2:]
        else:
            break
    action, chain, *rule = args
    key = f"{family}:{table}:{chain}"
    chains = state["chains"]
    failure = state.get("failure", {})
    if failure.get("action") == action and failure.get("chain") == chain:
        return 1
    if action == "-N":
        if key in chains:
            return 1
        chains[key] = []
    elif key not in chains:
        return 1
    elif action in ("-S", "-L"):
        print(f"-N {chain}")
        for item in chains[key]:
            print(f"-A {chain} {item}")
        return 0
    elif action == "-C":
        return 0 if " ".join(rule) in chains[key] else 1
    elif action == "-D":
        entry = " ".join(rule)
        if entry not in chains[key]:
            return 1
        chains[key].remove(entry)
    elif action == "-I":
        position = int(rule.pop(0)) - 1
        chains[key].insert(position, " ".join(rule))
    elif action == "-A":
        chains[key].append(" ".join(rule))
    elif action == "-F":
        chains[key] = []
    elif action == "-X":
        if chains[key] or any(f"-j {chain}" in rows for rows in chains.values()):
            return 1
        del chains[key]
    else:
        raise ValueError(f"Unexpected iptables action: {action}")
    state_path.write_text(json.dumps(state))
    return 0


if __name__ == "__main__":
    sys.exit(main())
