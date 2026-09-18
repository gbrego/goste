import json
import sys

def parse_policy(policy_path):
    try:
        with open(policy_path, "r") as f:
            data = json.load(f)
            
        print(f"--- Parsing {policy_path} ---")
        print(f"Total states: {len(data.get('states', []))}")
        for state in data.get("states", []):
            sid = state.get("id")
            symbol = state.get("probe", {}).get("symbol", "None")
            nxt = state.get("next", [])
            print(f"State {sid} [{symbol}] -> next: {nxt}")
            
    except Exception as e:
        print(f"Error: {e}")

parse_policy("/home/brego/Documents/Uni/Tesi/goste/benchmark/results/geth_evm_heavy_policy.json")
parse_policy("/home/brego/Documents/Uni/Tesi/goste/benchmark/results/geth_evm_refined_policy.json")
