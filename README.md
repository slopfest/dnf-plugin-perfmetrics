# DNF Plugin for Performance Metrics

This is a libdnf5 (DNF5) plug-in that records performance metrics for package
manager operations and stores them in JSON files under `/var/log/dnf5/perfmetrics`.

Each record captures the invoking process tree and command-line arguments, the
transaction's package actions (with sizes), and timing metrics reconstructed
from the libdnf5 plugin hooks:

- `repo_load_time` — repository metadata load
- `depsolve_time` — dependency resolution
- `rpm_transaction_time` — the rpm transaction itself
- `full_command_time` — total time the plug-in was loaded

Metrics are only written when running as root.

## Configuration

The plug-in is configured via `/etc/dnf/libdnf5-plugins/perfmetrics.conf`. The
`[main]` section accepts:

- `enabled` — set to `0` to disable the plug-in.
- `metrics_dir` — output directory (default `/var/log/dnf5/perfmetrics`).
- `retention_hours` — how long to keep metric files (default `4`).

## Building from Source

Build prerequisites: `gcc-c++`, `cmake`, `libdnf5-devel`, `json-c-devel`.

From the git checkout:

```
$ mkdir build
$ cmake -B build .
$ make -C build
$ sudo make -C build install
```

This installs the plug-in to `<libdir>/libdnf5/plugins/perfmetrics.so` and the
configuration to `/etc/dnf/libdnf5-plugins/perfmetrics.conf`.
