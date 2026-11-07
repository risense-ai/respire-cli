"""Stage an independent Runtime candidate for lifecycle acceptance.

Offline archives use the production CLI installer and its adjacent trusted
metadata. Explicit binaries require upstream provenance verification; their
dependency hashes come from core-runtime.json. The actual CLI enforces its pin.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile


def regular_file(root, name):
    parts = name.split("/")
    if not re.fullmatch(r"[A-Za-z0-9_./+-]+", name) or any(
        part in ("", ".", "..") for part in parts
    ):
        raise ValueError(f"unsafe Runtime bundle path: {name}")
    path = root
    for part in parts:
        path = path / part
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError(f"Runtime bundle contains a link: {name}")
    if not path.is_file():
        raise ValueError(f"Runtime bundle file missing: {name}")
    return path


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def copy_managed_installation(source_root, destination):
    source_root, destination = Path(source_root), Path(destination)
    receipt = regular_file(source_root, "runtime.json")
    selected = json.loads(receipt.read_text(encoding="utf-8"))
    version = selected["version"]
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+-]*", version) or not isinstance(
        selected.get("release", {}).get("metadata_json"), str
    ):
        raise ValueError("official managed Runtime receipt required")
    source = source_root / "runtime" / version
    runtime_name = "rsrs-runtime.exe" if os.name == "nt" else "rsrs-runtime"
    regular_file(source_root, f"runtime/{version}/{runtime_name}")
    files = []
    for path in source.rglob("*"):
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("managed Runtime fixture contains a link")
        if not path.is_dir():
            files.append(regular_file(source, path.relative_to(source).as_posix()))
    target = destination / "runtime" / version
    if target.exists() or (destination / "runtime.json").exists():
        raise ValueError("managed Runtime fixture destination must be fresh")
    shutil.copytree(source, target)
    for path in files:
        if digest(path) != digest(target / path.relative_to(source)):
            raise ValueError("managed Runtime fixture checksum mismatch")
    # Preserve the installer's original release proof; never synthesize a receipt.
    shutil.copy2(receipt, destination / "runtime.json")
    if receipt.read_bytes() != (destination / "runtime.json").read_bytes():
        raise ValueError("managed Runtime fixture receipt mismatch")
    return target / runtime_name


def stage_runtime(cli_binary, runtime_binary, destination, archive=None, version=None,
                  installation_root=None):
    if archive is not None:
        if runtime_binary is not None or not version:
            raise ValueError("archive requires a version and cannot be combined with a Runtime binary")
        # Reuse the production archive, binary and dependency verification.
        # The adjacent runtime-build-<triple>.json must come from trusted CI.
        with tempfile.TemporaryDirectory(prefix="respire-candidate-install-") as temporary:
            install_env = {key: value for key, value in os.environ.items()
                           if not key.startswith(("RSRS_", "RESPIRE_", "ONEMEMORY_"))}
            install_env.update(HOME=temporary, USERPROFILE=temporary,
                               RSRS_DATA_DIR=str(Path(temporary) / "data"),
                               RSRS_CORE_TEST_MODE="1", RSRS_UPDATE_CHECK="0", RSRS_NO_AUTOSYNC="1")
            installed = subprocess.run(
                [str(cli_binary), "--json", "runtime", "install", "--file", str(Path(archive).resolve(strict=True)), "--version", version],
                env=install_env, capture_output=True, text=True, timeout=180)
            if installed.returncode != 0:
                raise RuntimeError(f"verified Runtime install failed: {installed.stdout} {installed.stderr}")
            candidate = json.loads(installed.stdout)["summary"]["binary"]
            return stage_runtime(cli_binary, candidate, destination,
                                 installation_root=installation_root)
    if runtime_binary is None or version is not None:
        raise ValueError("supply a Runtime binary bundle or an archive with its version")
    cli_binary = Path(cli_binary).resolve(strict=True)
    runtime_binary = Path(runtime_binary).absolute()
    if not runtime_binary.is_file():
        raise ValueError(f"independent Runtime candidate missing: {runtime_binary}")
    root = runtime_binary.parent.resolve(strict=True)
    runtime_binary = regular_file(root, runtime_binary.name)
    if os.path.samefile(cli_binary, runtime_binary) or digest(cli_binary) == digest(runtime_binary):
        raise ValueError("independent Runtime required; CLI image cannot be the candidate")
    runtime_name = "rsrs-runtime.exe" if os.name == "nt" else "rsrs-runtime"
    manifest_path = regular_file(root, "core-runtime.json")
    if manifest_path.stat().st_size > 2 * 1024 * 1024:
        raise ValueError("Runtime dependency manifest is too large")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    files = manifest["files"]
    if manifest["schema_version"] != 1 or not manifest["target"] or not 0 < len(files) <= 4096:
        raise ValueError("invalid Runtime dependency manifest")
    selected = [(runtime_binary, runtime_name), (manifest_path, "core-runtime.json")]
    seen = {runtime_name.casefold(), "core-runtime.json", "rsrs", "rsrs.exe"}
    for entry in files:
        name, expected = entry["path"], entry["sha256"]
        if name.casefold() in seen or not re.fullmatch(r"[0-9a-fA-F]{64}", expected):
            raise ValueError(f"duplicate, reserved or invalid Runtime dependency: {name}")
        seen.add(name.casefold())
        source = regular_file(root, name)
        if digest(source) != expected.lower():
            raise ValueError(f"Runtime dependency checksum mismatch: {name}")
        selected.append((source, name))
    destination = Path(destination)
    if destination.exists():
        raise ValueError("Runtime acceptance destination must be fresh")
    if installation_root is not None:
        if root.parent.name != "runtime":
            raise ValueError("managed Runtime candidate required for host control")
        installed = copy_managed_installation(root.parent.parent, installation_root)
        if root.name != installed.parent.name or digest(runtime_binary) != digest(installed):
            raise ValueError("Runtime candidate does not match the managed installation")
    # Validate the complete allowlist before copying anything into the fixture.
    for source, name in selected:
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        if digest(source) != digest(target):
            raise ValueError(f"staged Runtime checksum mismatch: {name}")
    return destination / runtime_name


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--runtime-binary", type=Path)
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--version")
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    stage_runtime(args.binary, args.runtime_binary, args.destination, args.archive, args.version)
