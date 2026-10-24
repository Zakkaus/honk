#!/usr/bin/env bash
set -euo pipefail

ci_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"

expect_rejection() {
  local prefix=$1 status=0
  bash "$ci_dir/check-release-artifacts.sh" "$prefix" > failure.log 2>&1 || status=$?
  if [[ "$status" != 1 ]]; then
    cat failure.log >&2
    printf 'Expected incomplete %s artifacts to be rejected, got exit %s\n' "$prefix" "$status" >&2
    exit 1
  fi
}

# Debug builds and formal tags share the sixteen-archive set; only the name prefix differs.
for prefix in debug v0.1.0-rc.1; do
  mkdir dist
  for target in x86_64-unknown-linux-gnu x86_64-unknown-linux-musl aarch64-unknown-linux-gnu aarch64-unknown-linux-musl; do
    for suffix in '' -stock; do
      printf 'artifact\n' > "dist/honk-core-$prefix-$target$suffix-full.tar.gz"
    done
  done
  for target in x86_64-unknown-linux-musl aarch64-unknown-linux-musl; do
    for suffix in '' -stock; do
      printf 'artifact\n' > "dist/honk-core-$prefix-$target$suffix-clash-api.tar.gz"
      printf 'artifact\n' > "dist/honk-core-$prefix-$target$suffix-native-api.tar.gz"
    done
  done
  bash "$ci_dir/check-release-artifacts.sh" "$prefix"

  artifact=dist/honk-core-$prefix-aarch64-unknown-linux-musl-stock-native-api.tar.gz
  mv "$artifact" saved.tar.gz
  expect_rejection "$prefix"
  mv saved.tar.gz "$artifact"
  bash "$ci_dir/check-release-artifacts.sh" "$prefix"

  artifact=dist/honk-core-$prefix-x86_64-unknown-linux-gnu-full.tar.gz
  mv "$artifact" saved.tar.gz
  expect_rejection "$prefix"
  mv saved.tar.gz "$artifact"
  bash "$ci_dir/check-release-artifacts.sh" "$prefix"

  : > "$artifact"
  expect_rejection "$prefix"
  rm "$artifact"
  mkdir "$artifact"
  expect_rejection "$prefix"
  rm -r dist
  expect_rejection "$prefix"
done

# The other prefix's archives do not satisfy the check.
mkdir -p dist
printf 'artifact\n' > dist/honk-core-debug-x86_64-unknown-linux-gnu-full.tar.gz
expect_rejection v0.1.0-rc.1

printf 'Release artifact preflight regression passed\n'
