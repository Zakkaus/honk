Added

- The `embedded` cargo feature (off by default) adds `honk_core::embedded::Engine`, which decides routing for flows that an application captures itself, such as from a TUN device. It returns the matched rule, its `must` modifier, the mode result, the selected outbound and its candidate nodes, computed by the daemon's own router, mode override and group selection.
