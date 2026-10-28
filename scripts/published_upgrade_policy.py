"""Explicit historical gaps; a missing asset is never a general skip rule."""
ARM_TARGETS = frozenset({"aarch64-unknown-linux-gnu", "aarch64-unknown-linux-musl"})
ABSENT_ARM_RELEASES = frozenset({"v1.0.15", "v1.0.16", "v1.0.17-dev.12"})


def platform_applicability(tag, target, asset_names):
    extension = ".exe" if "windows" in target else ""
    required = {f"rsrs-{target}{extension}", f"rsrs-{target}-runtime.tar.gz", f"cli-build-{target}.json"}
    present = required.intersection(asset_names)
    if present == required:
        return None
    if target in ARM_TARGETS and tag in ABSENT_ARM_RELEASES and not present:
        return "Linux ARM64 was not distributed for this exact release"
    raise ValueError(f"missing platform artifact: {tag} {target}; present={sorted(present)}")
