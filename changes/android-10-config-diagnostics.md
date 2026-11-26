Changed

- Validation refusals carry the line and byte column of their setting, or of the nearest written entry, block or section, in native API full validation and in startup errors.
- A router build failure, such as an invalid `regex:` pattern or port, names its rule as `routing.rules[N]`.
- Offline geodata admission names the missing geosite or GeoIP category.
- `Config::validate_detailed` refuses nil or duplicate subscription IDs at `subscriptions[i].id`.
