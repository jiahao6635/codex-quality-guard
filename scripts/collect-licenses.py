#!/usr/bin/env python3
"""为当前 Cargo.lock 汇总实际依赖许可；不执行依赖代码。"""

import hashlib
import json
from pathlib import Path
import re
import subprocess


ROOT = Path(__file__).resolve().parent.parent
metadata_command = [
    "cargo", "metadata", "--locked", "--format-version", "1",
    "--manifest-path", str(ROOT / "backend/Cargo.toml"),
]
cached = subprocess.run(metadata_command + ["--offline"], capture_output=True, text=True)
if cached.returncode == 0:
    metadata = json.loads(cached.stdout)
else:
    # 新 CI 缓存可能缺少其他平台的源码，仅获取锁文件已固定的依赖。
    print("Fetching locked dependency sources needed for license notices.")
    metadata = json.loads(subprocess.check_output(metadata_command, text=True))
packages = sorted(metadata["packages"], key=lambda item: (item["name"], item["version"]))
project = next(item for item in packages if item["name"] == "codex-quality-guard")
sections = [
    "Codex Quality Guard — license notices\n\n"
    "Generated from Cargo.lock and the dependencies' actual license files.\n"
    "This includes build, test and conditional-platform dependencies conservatively.\n"
    "Where MIT is offered as an alternative, this distribution selects MIT.\n"
    "Additional Unicode data terms are retained where required.\n",
]


def section(title, source, declared, files, selected):
    text = ["=" * 78, title, f"Source: {source}",
            f"Declared license: {declared}", f"Included license: {selected}"]
    for path in files:
        text.extend([f"\n--- {path.name} ---\n", path.read_text(encoding="utf-8").rstrip()])
    sections.append("\n".join(text) + "\n")


section(f"codex-quality-guard {project['version']}", "This repository", "MIT",
        [ROOT / "LICENSE"], "MIT")

modeltrace = ROOT / "data/modeltrace"
provenance = json.loads((modeltrace / "provenance.json").read_text())
license_file = modeltrace / "LICENSE"
assert hashlib.sha256(license_file.read_bytes()).hexdigest() == provenance["files"]["LICENSE"]["sha256"]
section("ModelTrace fingerprint data and adapted fingerprint/challenge logic",
        f"{provenance['repository']} @ {provenance['commit']}", "MIT", [license_file], "MIT")
sections.append("ModelTrace logic was adapted to Rust with local validation and probe safeguards.\n")

for package in packages:
    if package["name"] == project["name"]:
        continue
    directory = Path(package["manifest_path"]).parent
    files = {path.name.lower(): path for path in directory.iterdir() if path.is_file()}
    declared = package.get("license") or ""
    chosen = []
    selected = ""
    if re.search(r"\bMIT\b", declared):
        # 当前锁文件仅有 Unicode 的附加 AND 条款；新表达式要求显式检查。
        if " AND " in declared and declared != "(MIT OR Apache-2.0) AND Unicode-3.0":
            raise RuntimeError(f"Review new license expression: {package['name']}: {declared}")
        mit = files.get("license-mit") or files.get("license")
        if mit is None or "Permission is hereby granted" not in mit.read_text(encoding="utf-8"):
            raise RuntimeError(f"Missing MIT license text: {package['name']}")
        chosen.append(mit)
        selected = "MIT"
        if "Unicode-3.0" in declared:
            chosen.append(files["license-unicode"])
            selected += " AND Unicode-3.0"
    elif package["name"] == "gateway-plugin-sdk" and declared == "Apache-2.0":
        # SDK 继承固定 Git checkout 根目录许可，crate 目录内没有副本。
        sdk_root = next(parent for parent in directory.parents if (parent / "LICENSE").is_file())
        chosen.append(sdk_root / "LICENSE")
        files.update({path.name.lower(): path for path in sdk_root.iterdir() if path.is_file()})
        selected = "Apache-2.0"
    else:
        raise RuntimeError(f"Review dependency license: {package['name']}: {declared}")
    chosen.extend(path for name, path in sorted(files.items()) if name.startswith("notice"))
    source = package["source"]
    if source.startswith("registry+"):
        source = f"https://crates.io/crates/{package['name']}/{package['version']}"
    section(f"{package['name']} {package['version']}", source, declared, chosen, selected)

output = ROOT / "legal/notices.txt"
output.parent.mkdir(exist_ok=True)
output.write_text("\n".join(sections), encoding="utf-8")
print(f"Collected project, ModelTrace and {len(packages) - 1} Cargo dependency notices.")
