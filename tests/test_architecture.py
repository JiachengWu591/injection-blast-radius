"""The dependency layering is computed, not declared.

ARCHITECTURE.md draws a layered graph. A drawing goes stale the first time
someone adds an import, and nothing fails — the diagram just quietly starts
lying, which is worse than having no diagram because a reader trusts it.

So the layers here are derived from the actual imports, and the assertions
check the properties the drawing claims: no cycles, no module importing from a
layer above its own, and `schemas` in particular depending on nothing at all.

That last one is the load-bearing property. The structural guarantee is only
checkable without a network because the contracts do not reach for the
filesystem, the provider, or the logger. An import added to `schemas` would not
break any behavioural test and would quietly end that.

Run standalone:
    python tests/test_architecture.py
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "ibr"

# The intended layering, as ARCHITECTURE.md draws it. Checked against the
# computed one rather than trusted: if they disagree, one of them is wrong and
# the test says which module moved.
DECLARED_LAYERS: dict[str, int] = {
    "config": 0,
    "schemas": 0,
    "output_audit": 0,
    "fixtures": 0,
    "llm": 1,
    "sandbox_fs": 1,
    "bootstrap": 2,
    "issues": 2,
    "observability": 2,
    "sinks": 2,
    "attack_corpus": 3,
    "baseline_agent": 3,
    "executor": 3,
    "sources": 3,
    "pipeline": 4,
    "comparison": 5,
    "variance": 5,
    "report": 6,
}

# Modules that must keep depending on nothing inside the package. These are the
# ones the offline security assertions rest on.
MUST_STAY_INDEPENDENT = {"schemas", "output_audit", "config"}


def _modules() -> list[str]:
    return sorted(p.stem for p in PACKAGE.glob("*.py") if p.stem != "__init__")


def _intra_package_imports() -> dict[str, set[str]]:
    """Map each module to the sibling modules it imports.

    Only relative imports (`from .x import y`) count, which is exactly the
    package-internal coupling the layering is about.
    """
    modules = set(_modules())
    graph: dict[str, set[str]] = {}
    for name in sorted(modules):
        tree = ast.parse((PACKAGE / f"{name}.py").read_text(encoding="utf-8"))
        deps: set[str] = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.ImportFrom) or node.level != 1:
                continue
            if node.module:
                deps.add(node.module.split(".")[0])
            else:  # from . import x, y
                deps.update(alias.name for alias in node.names)
        graph[name] = {d for d in deps if d in modules}
    return graph


def _computed_layers(graph: dict[str, set[str]]) -> dict[str, int]:
    """Longest path to a leaf, which is the only layering that is well defined."""
    layers: dict[str, int] = {}
    remaining = dict(graph)
    while remaining:
        ready = [m for m, deps in remaining.items() if deps <= layers.keys()]
        if not ready:
            raise AssertionError(
                f"import cycle among {sorted(remaining)} — the layering is not a DAG"
            )
        for module in ready:
            layers[module] = (
                max((layers[d] for d in remaining[module]), default=-1) + 1
            )
        for module in ready:
            del remaining[module]
    return layers


def test_the_dependency_graph_is_acyclic() -> None:
    """A cycle would make "which layer is this" unanswerable."""
    _computed_layers(_intra_package_imports())


def test_dependency_layers_have_not_inverted() -> None:
    """No module may import from a layer above its own.

    Stated as an inequality rather than an equality: a module is allowed to
    stop using a dependency and float downward. What it may not do is reach
    upward, because that is what turns a layered package into a tangle.
    """
    graph = _intra_package_imports()
    declared = DECLARED_LAYERS
    unknown = sorted(set(graph) - set(declared))
    assert not unknown, (
        f"module(s) {unknown} are not in DECLARED_LAYERS. Add them to "
        "tests/test_architecture.py and to ARCHITECTURE.md, so a new module "
        "cannot join the package without a stated place in the order."
    )
    gone = sorted(set(declared) - set(graph))
    assert not gone, f"DECLARED_LAYERS lists module(s) that no longer exist: {gone}"

    violations = [
        f"{module} (layer {declared[module]}) imports {dep} (layer {declared[dep]})"
        for module, deps in graph.items()
        for dep in sorted(deps)
        if declared[dep] >= declared[module]
    ]
    assert not violations, "dependency inversion:\n  " + "\n  ".join(violations)


def test_the_declared_layers_match_the_computed_ones() -> None:
    """ARCHITECTURE.md's drawing must describe the code that exists."""
    graph = _intra_package_imports()
    computed = _computed_layers(graph)
    mismatched = {
        module: (DECLARED_LAYERS[module], computed[module])
        for module in computed
        if DECLARED_LAYERS[module] != computed[module]
    }
    assert not mismatched, (
        "declared layer != computed layer for "
        + ", ".join(
            f"{m} (declared {d}, computed {c})" for m, (d, c) in mismatched.items()
        )
        + ". Update ARCHITECTURE.md and DECLARED_LAYERS together."
    )


def test_the_contract_modules_depend_on_nothing() -> None:
    """The reason the security assertions can run without a network.

    `schemas` is the structural boundary. If it grew an import of `sandbox_fs`
    or `llm`, every behavioural test would still pass and the claim that the
    guarantee is independent of the filesystem and the provider would quietly
    stop being true.
    """
    graph = _intra_package_imports()
    for module in sorted(MUST_STAY_INDEPENDENT):
        assert graph[module] == set(), (
            f"{module} must not import from inside the package, but imports "
            f"{sorted(graph[module])}. That module is depended on by almost "
            "everything; giving it dependencies of its own inverts the package."
        )


def test_the_architecture_document_lists_every_module() -> None:
    """A module absent from the document is a module nobody will find."""
    for doc_name in ("ARCHITECTURE.md", "ARCHITECTURE.zh-CN.md"):
        document = (ROOT / doc_name).read_text(encoding="utf-8")
        missing = [m for m in _modules() if m not in document]
        assert not missing, f"{doc_name} does not mention: {missing}"


def main() -> int:
    tests = [
        (name, fn)
        for name, fn in sorted(globals().items())
        if name.startswith("test_") and callable(fn)
    ]
    failures = 0
    for name, fn in tests:
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 - the runner reports, never hides
            failures += 1
            print(f"FAIL  {name}\n        {type(exc).__name__}: {exc}")
        else:
            print(f"pass  {name}")

    graph = _intra_package_imports()
    computed = _computed_layers(graph)
    depth = max(computed.values()) + 1
    print(f"\n{len(graph)} modules in {depth} layers, no cycles")
    print(f"{len(tests) - failures}/{len(tests)} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
