import json
from pathlib import Path

MANIFEST = Path(__file__).resolve().parents[2] / "ida-plugin.json"


def test_manifest_is_valid_json_with_required_fields():
    data = json.loads(MANIFEST.read_text())
    assert data["IDAMetadataDescriptorVersion"] == 1
    assert data["$schema"].startswith("https://hcli.docs.hex-rays.com/")
    plugin = data["plugin"]
    assert plugin["name"] == "mcpyida"
    assert plugin["entryPoint"] == "mcpyida_plugin.py"
    assert plugin["version"]  # placeholder is allowed
    assert plugin["urls"]["repository"] == "https://github.com/nightwing-us/mcpyida"
    assert any(a.get("name") for a in plugin["authors"])
    assert plugin["license"] == "Apache-2.0"


def test_manifest_pins_mcpyida_pypi_dependency():
    data = json.loads(MANIFEST.read_text())
    deps = data["plugin"]["pythonDependencies"]
    assert any(d.startswith("mcpyida==") for d in deps)


def test_manifest_targets_ida9():
    data = json.loads(MANIFEST.read_text())
    assert "9.0" in data["plugin"]["idaVersions"]


# Valid plugin.categories values accepted by the IDA Plugin Manager
# (hcli/lib/ida/plugin: PluginMetadata.categories Literal set).
VALID_CATEGORIES = {
    "disassembly-and-processor-modules",
    "file-parsers-and-loaders",
    "decompilation",
    "debugging-and-tracing",
    "deobfuscation",
    "collaboration-and-productivity",
    "integration-with-third-parties-interoperability",
    "api-scripting-and-automation",
    "ui-ux-and-visualization",
    "malware-analysis",
    "vulnerability-research-and-exploit-development",
    "other",
}


def test_manifest_categories_are_present_and_valid():
    categories = json.loads(MANIFEST.read_text())["plugin"]["categories"]
    assert categories, "expected at least one category for discoverability"
    assert set(categories) <= VALID_CATEGORIES, (
        f"invalid categories: {set(categories) - VALID_CATEGORIES}"
    )
