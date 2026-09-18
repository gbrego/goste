import json

policy_path = "/home/brego/Documents/Uni/Tesi/goste/benchmark/results_coredns_new/original_coredns_intensive_policy.json"

try:
    with open(policy_path, "r") as f:
        data = json.load(f)
        
    print(f"Total states: {len(data.get('states', []))}")
    for state in data.get("states", []):
        sid = state.get("id")
        nxt = state.get("next", [])
        print(f"State {sid} -> next: {nxt}")
        
except Exception as e:
    print(f"Error: {e}")
