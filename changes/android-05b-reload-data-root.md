Changed

- An engine built with an explicit data root (`DataRoot::explicit`) also reads geodata, `use_host` files and a relative `log_file` path from that directory when it reloads its configuration. The daemon's root and search order are unchanged.
