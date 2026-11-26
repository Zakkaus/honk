Added

- `honk_core::embedded::Engine` runs honk's health checks through the application's outbounds (`start_health`), so URLTest, Fallback, LoadBalance and Score groups choose by honk's probes. It also sets a Selector group's member at runtime (`select`), runs the Clash API's node and group delay tests (`test_node`, `test_group`), and reports each group's members, choice, liveness and last latency (`groups`).
