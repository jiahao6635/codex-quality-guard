#!/usr/bin/env bash
set -euo pipefail

plugin_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
plugin_target="${1:-$(rustc -vV | awk '/^host: / {print $2}')}"
case "$plugin_target" in
  x86_64-unknown-linux-gnu|aarch64-unknown-linux-gnu|aarch64-apple-darwin) ;;
  *) echo "Unsupported plugin target: $plugin_target" >&2; exit 1 ;;
esac

# 与插件固定到同一 SDK 提交，避免全局安装的旧 CLI 改写清单合同。
sdk_source="$(cargo metadata --manifest-path "$plugin_root/backend/Cargo.toml" --locked --no-deps --format-version 1 | python3 -c '
import json, sys
packages = json.load(sys.stdin)["packages"]
package = next(p for p in packages if p["name"] == "codex-quality-guard")
print(next(d["source"] for d in package["dependencies"] if d["name"] == "gateway-plugin-sdk"))
')"
sdk_git="${sdk_source#git+}"
sdk_git="${sdk_git%%\?*}"
sdk_rev="${sdk_source##*\?rev=}"
if [[ "$sdk_source" != git+*\?rev=* ]] || [[ ! "$sdk_rev" =~ ^[0-9a-f]{40}$ ]]; then
  echo 'gateway-plugin-sdk must use a Git dependency pinned to a full commit.' >&2
  exit 1
fi
plugin_tools="$plugin_root/.cache/cpr-plugin/$sdk_rev"
if [[ ! -x "$plugin_tools/bin/cpr-plugin" ]]; then
  cargo install --locked --git "$sdk_git" --rev "$sdk_rev" \
    --root "$plugin_tools" --bin cpr-plugin codex-proxy-plugin-cli
fi

cargo build --manifest-path "$plugin_root/backend/Cargo.toml" \
  --release --locked --target "$plugin_target" --target-dir "$plugin_root/backend/target"
python3 "$plugin_root/scripts/collect-licenses.py"
"$plugin_tools/bin/cpr-plugin" package \
  --manifest "$plugin_root/plugin.json" \
  --binary "$plugin_root/backend/target/$plugin_target/release/codex-quality-guard" \
  --target "$plugin_target" \
  --resource-map legal=legal \
  --resource-map web=web \
  --output-dir "$plugin_root/dist"
