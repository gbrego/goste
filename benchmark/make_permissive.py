import json
import glob
import os
import shutil

# Base directories where policies might be stored
search_dirs = [
    "/home/brego/Documents/Uni/Tesi/goste/benchmark/results",
    "/home/brego/Documents/Uni/Tesi/industryTargetsAlpha/geth-bench",
    "/home/brego/Documents/Uni/Tesi/industryTargetsAlpha"
]

# Additional syscalls seen in the user's log just in case they aren't in any state
extra_syscalls = [
    "listen", "mkdirat", "unlinkat", "getdents64", "flock", "pwrite64",
    "fdatasync", "lseek", "fallocate", "renameat", "futex", "epoll_wait",
    "sched_yield", "epoll_pwait", "accept4", "write", "rt_sigreturn"
]

def make_permissive(filepath):
    try:
        with open(filepath, 'r') as f:
            data = json.load(f)
    except Exception as e:
        print(f"Error reading {filepath}: {e}")
        return

    if "states" not in data:
        return

    # 1. Collect all unique syscalls across all states
    all_syscalls = set(extra_syscalls)
    max_state_id = 0
    for state in data["states"]:
        if "id" in state and state["id"] > max_state_id:
            max_state_id = state["id"]
        if state.get("syscalls"):
            for sc in state["syscalls"]:
                all_syscalls.add(sc)

    all_syscalls_list = sorted(list(all_syscalls))
    
    # 2. Allow all states up to 63 to transition to any state (engine limit is 64)
    all_nexts = list(range(64))

    # 3. Apply to all states, filling in missing ones up to 63
    modified = False
    existing_states = {state.get("id", 0): state for state in data["states"]}
    
    new_states = []
    for state_id in range(64):
        if state_id in existing_states:
            state = existing_states[state_id]
        else:
            state = {"id": state_id}
            
        original_syscalls = len(state.get("syscalls") or [])
        original_nexts = len(state.get("next") or [])
        
        if original_syscalls != len(all_syscalls_list):
            state["syscalls"] = all_syscalls_list
            modified = True
            
        if original_nexts != len(all_nexts):
            state["next"] = all_nexts
            modified = True
            
        new_states.append(state)

    if modified:
        data["states"] = new_states
        
        dirname = os.path.dirname(filepath)
        basename = os.path.basename(filepath)
        original_filepath = os.path.join(dirname, f"original_{basename}")
        if not os.path.exists(original_filepath):
            try:
                shutil.copy2(filepath, original_filepath)
                print(f"Saved original to {original_filepath}")
            except Exception as e:
                print(f"Failed to backup {filepath}: {e}")
                
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"Updated {filepath} to be maximally permissive.")

if __name__ == "__main__":
    for d in search_dirs:
        for root, _, files in os.walk(d):
            for file in files:
                if file.endswith("policy.json") and "tracing_output" not in file and not file.startswith("original_"):
                    make_permissive(os.path.join(root, file))

    print("Done.")
