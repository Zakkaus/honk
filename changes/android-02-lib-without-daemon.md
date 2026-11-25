Changed

- The `honk-core` binary, its command-line parser and subcommands, and systemd notifications now sit behind the default-on `daemon` Cargo feature, so `honk-core` builds as a library without `clap` or `libsystemd`. Builds that pass `--no-default-features` and need the binary must add `daemon` to `--features`.
- `honk-core` builds for non-Linux targets such as Android. Sending a DNS reply from a chosen source address needs Linux and reports `Unsupported` elsewhere.
