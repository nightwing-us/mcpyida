import importlib.util
import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location(
    "inject_plugin_version", REPO / "scripts" / "inject-plugin-version.py"
)
inj = importlib.util.module_from_spec(_spec)


def _load():
    _spec.loader.exec_module(inj)


def _manifest():
    return {
        "$schema": "https://hcli.docs.hex-rays.com/schemas/ida-plugin.json",
        "IDAMetadataDescriptorVersion": 1,
        "plugin": {
            "name": "mcpyida",
            "version": "0.0.0",
            "entryPoint": "mcpyida_plugin.py",
            "urls": {"repository": "https://github.com/nightwing-us/mcpyida"},
            "authors": [{"name": "Eric Lin"}],
            "pythonDependencies": ["mcpyida==0.0.0"],
            "idaVersions": ["9.0"],
        },
    }


def test_inject_sets_version_and_pin(tmp_path):
    _load()
    m = tmp_path / "ida-plugin.json"
    m.write_text(json.dumps(_manifest()))
    inj.inject(str(m), "1.2.3")
    data = json.loads(m.read_text())
    assert data["plugin"]["version"] == "1.2.3"
    assert "mcpyida==1.2.3" in data["plugin"]["pythonDependencies"]
    assert "0.0.0" not in m.read_text()


def test_inject_preserves_other_dependencies(tmp_path):
    _load()
    man = _manifest()
    man["plugin"]["pythonDependencies"] = ["mcpyida==0.0.0", "requests>=2"]
    m = tmp_path / "ida-plugin.json"
    m.write_text(json.dumps(man))
    inj.inject(str(m), "2.0.0")
    deps = json.loads(m.read_text())["plugin"]["pythonDependencies"]
    assert "mcpyida==2.0.0" in deps
    assert "requests>=2" in deps
