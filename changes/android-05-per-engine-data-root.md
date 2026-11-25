Internal

- Geodata, hosts, state, log and native UI paths resolve through a per-engine data root (`DataRoot`). An explicit root searches only its own directory: it ignores `$DAE_LOCATION_ASSET`, the old data directory, the working directory and the honk and dae share directories. The daemon keeps its search order.
- A test now fails when production code reads the process-wide data directory outside a listed site.
