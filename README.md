# GoSTE

Powerful real-time, syscall observability and runtime enforcement for Go applications.

## Getting started

Ensure Go is installed on your system and that you are running Linux kernel 6.6 or newer.

Install `clang`, `bpftool` and Linux headers for your kernel version.

Before building, generate the required syscalls list by running:
```shell
go generate ./...
```

Then, compile with `make`. You can also generate eBPF bindings and build the
program separately using make targets.

## Usage

GoSTE operates in two main modes: `trace` to generate a security policy, and `enforce` to apply it.

### Tracing (Generating a Policy)

To trace a command from the beginning and save the generated policy:
```shell
sudo ./goste trace -o policy.json /path/to/target
```
Then stop the daemon to finish gathering the invoked syscalls and save the `policy.json` file.

To attach to an existing process, specify the target's PID:
```shell
sudo ./goste trace -o policy.json -p <PID>
```

### Enforcement (Applying a Policy)

Once you have a policy, you can enforce it using the `enforce` command. You can specify the action to take on a violation using the `-a` flag (`log`, `errno`, or `kill-process`).

To enforce a policy on a new command:
```shell
sudo ./goste enforce -a errno policy.json /path/to/target
```

To enforce a policy on an existing process:
```shell
sudo ./goste enforce -a errno -p <PID> policy.json
```

## Benchmarks

If you want to run the automated benchmarks, make sure to change the paths in `benchmark/config.yaml` to your local binaries. Further customized profiles can be easily added.

## References

GoSTE inherits its core principles from the Syscomb project, and extends them to Go targets. For more details on the theoretical foundation, please refer to:

* **SysComb: Fine-Grained Transparent System Call Filtering for Attack Surface Reduction**
  [arXiv:2608.26871](https://arxiv.org/abs/2608.26871)
