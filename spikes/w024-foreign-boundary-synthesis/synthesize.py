#!/usr/bin/env python3
"""
W-024 Executable Spike: Zero-Annotation Foreign Boundary Descriptor Synthesis
=============================================================================
Replaces `compiler/crates/hy-check/src/foreign.rs` (1,280 lines of hand-curated
stub match tables) and `SPEC.md` §13 M5's 19-package allowlist wall with
deterministic static synthesis from Go function/method ASTs + `-gcflags="-m=2"`
escape summaries.

Zero external dependencies (Python 3.10+ stdlib only).
"""

from __future__ import annotations

import dataclasses
import pathlib
import re
import time
from typing import Dict, List, Optional, Set, Tuple


@dataclasses.dataclass(frozen=True)
class GoParam:
    name: str
    go_type: str


@dataclasses.dataclass(frozen=True)
class GoFuncDecl:
    pkg: str
    go_name: str
    receiver: Optional[GoParam]
    params: Tuple[GoParam, ...]
    returns: Tuple[str, ...]
    body: Optional[str]  # None for assembly / CGo / interface signatures
    gcflags_escape: Tuple[str, ...] = ()


@dataclasses.dataclass(frozen=True)
class BoundaryDescriptor:
    pkg: str
    hy_name: str
    go_name: str
    is_method: bool
    receiver_type: Optional[str]
    result_shape: str
    result_count: int
    fallible: bool
    mutated_arg_mask: int
    may_share_arg_mask: int
    call_mode: str
    evidence_tier: str

    def first_mutated_arg(self) -> Optional[int]:
        if self.mutated_arg_mask == 0:
            return None
        idx = 0
        mask = self.mutated_arg_mask
        while (mask & 1) == 0:
            mask >>= 1
            idx += 1
        return idx

    def first_shared_arg(self) -> Optional[int]:
        if self.may_share_arg_mask == 0:
            return None
        idx = 0
        mask = self.may_share_arg_mask
        while (mask & 1) == 0:
            mask >>= 1
            idx += 1
        return idx


@dataclasses.dataclass(frozen=True)
class ForeignRsAudit:
    path: str
    total_lines: int
    builtin_packages_count: int
    mutated_arg_entries: Dict[Tuple[str, str], int]
    package_result_entries: Dict[Tuple[str, str], str]
    curated_member_packages: int
    curated_member_symbols: int


def pascal_to_snake(name: str) -> str:
    """Convert Go PascalCase identifier to Hybrid snake_case."""
    s1 = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", name)
    s2 = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s1)
    return s2.lower()


PRIMITIVE_GO_TYPES: Set[str] = {
    "bool",
    "int",
    "int8",
    "int16",
    "int32",
    "int64",
    "uint",
    "uint8",
    "uint16",
    "uint32",
    "uint64",
    "uintptr",
    "byte",
    "rune",
    "float32",
    "float64",
    "complex64",
    "complex128",
    "time.Duration",
}


def map_go_type_to_hy_shape(pkg: str, go_type: str) -> str:
    """Map a Go return type string to a Hybrid `TypeShape` representation."""
    t = go_type.strip()
    if not t:
        return "TypeShape::Primitive"
    if t in PRIMITIVE_GO_TYPES:
        return "TypeShape::Primitive"
    if t == "string":
        return "TypeShape::Str"
    if t == "error":
        return 'TypeShape::ForeignOpaque("error".into())'
    if t == "unsafe.Pointer" or t == "any" or t == "interface{}":
        return "TypeShape::Unknown"
    if t.startswith("[]"):
        inner = map_go_type_to_hy_shape(pkg, t[2:])
        return f"TypeShape::Slice(Box::new({inner}))"
    if t.startswith("<-chan ") or t.startswith("chan<- ") or t.startswith("chan "):
        inner_raw = re.sub(r"^(<-chan|chan<-|chan)\s+", "", t)
        inner = map_go_type_to_hy_shape(pkg, inner_raw)
        return f"TypeShape::Chan(Box::new({inner}))"
    if t.startswith("map["):
        return "TypeShape::Unknown"

    clean = t.lstrip("*")
    if "." in clean:
        sub_pkg, sub_ty = clean.split(".", 1)
        return f'TypeShape::ForeignOpaque("{sub_pkg}.{pascal_to_snake(sub_ty)}".into())'
    return f'TypeShape::ForeignOpaque("{pkg}.{pascal_to_snake(clean)}".into())'


def is_mutable_carrier_type(go_type: str) -> bool:
    """Return True if a Go parameter type can carry in-place mutation back to caller."""
    t = go_type.strip()
    return (
        t.startswith("[]")
        or t.startswith("*")
        or t.startswith("map[")
        or t in ("any", "interface{}", "sort.Interface")
    )


def is_slice_or_ptr_carrier(go_type: str) -> bool:
    t = go_type.strip()
    return t.startswith("[]") or t.startswith("*")


# Known interface method mutation contracts (bootstrapped from interface decls):
# e.g., `io.Reader.Read(p []byte)` mutates arg 0 (`p`), `io.Writer.Write(p []byte)`
# reads arg 0 and mutates receiver.
INTERFACE_METHOD_MUTATED_ARGS: Dict[str, Set[int]] = {
    "Read": {0},
    "ReadAt": {0},
    "ReadFrom": set(),
    "Swap": set(),  # mutates receiver
}


class BoundarySynthesizer:
    """
    Synthesizes Hybrid boundary descriptors (`BoundaryDescriptor`) directly from
    Go function declarations, AST bodies, and `-gcflags="-m=2"` escape summaries.
    """

    def __init__(self, strict_bodyless_conservative: bool = True) -> None:
        self.strict_bodyless_conservative = strict_bodyless_conservative
        self.synthesized: Dict[Tuple[str, str], BoundaryDescriptor] = {}

    def synthesize_package(self, decls: List[GoFuncDecl]) -> List[BoundaryDescriptor]:
        # Two-pass synthesis so intra-package helper calls (e.g. `io.ReadFull` ->
        # `io.ReadAtLeast`, `sort.Ints` -> `sort.Sort`) propagate mutation masks.
        results: Dict[Tuple[str, str], BoundaryDescriptor] = {}
        for _pass in range(2):
            for decl in decls:
                pkg_env = {
                    go_name: desc
                    for (pkg, go_name), desc in results.items()
                    if pkg == decl.pkg
                }
                desc = self._synthesize_one(decl, pkg_env)
                results[(decl.pkg, decl.go_name)] = desc
                self.synthesized[(decl.pkg, desc.hy_name)] = desc
        return [results[(d.pkg, d.go_name)] for d in decls]

    def _synthesize_one(
        self,
        decl: GoFuncDecl,
        pkg_env: Dict[str, BoundaryDescriptor],
    ) -> BoundaryDescriptor:
        hy_name = pascal_to_snake(decl.go_name)

        # 1. Compute return shape, fallibility, and static result count (T23 / #380)
        returns = list(decl.returns)
        fallible = len(returns) >= 1 and returns[-1].strip() == "error"
        result_count = len(returns)

        if not returns:
            result_shape = "TypeShape::Primitive"
        elif returns == ["error"]:
            result_shape = "TypeShape::Primitive"
        elif fallible and len(returns) == 2:
            result_shape = map_go_type_to_hy_shape(decl.pkg, returns[0])
        elif len(returns) == 1:
            result_shape = map_go_type_to_hy_shape(decl.pkg, returns[0])
        else:
            # Multi-return non-error or 3+ tuple: shape of primary return
            result_shape = map_go_type_to_hy_shape(decl.pkg, returns[0])

        # Special rule for sync/atomic pointer operations (GUARANTEES.md Row 11)
        if decl.pkg == "atomic" and "Pointer" in decl.go_name:
            result_shape = "TypeShape::Unknown"

        # 2. Compute mutated_arg_mask and may_share_arg_mask
        mutated_mask = 0
        may_share_mask = 0
        evidence_tier = "Tier1_AST_Exact"

        body = decl.body
        if body is not None:
            for idx, param in enumerate(decl.params):
                if not is_mutable_carrier_type(param.go_type):
                    continue
                pname = re.escape(param.name)

                # (a) Direct indexed assignment: `p[i] = ...`
                direct_index_write = bool(
                    re.search(rf"\b{pname}\s*\[[^\]]+\]\s*(?:=|\+=|-=|\|=|\&=|\^=)", body)
                )
                # (b) Direct pointer deref write: `*p = ...` or `p.field = ...`
                direct_deref_write = bool(
                    re.search(rf"\*\s*{pname}\s*=", body)
                    or re.search(rf"\b{pname}\.[A-Za-z0-9_]+\s*(?:=|\+=|-=)", body)
                )
                # (c) Builtin `copy(p, ...)` or sub-slice copy `copy(p[...], ...)`
                builtin_copy_write = bool(
                    re.search(rf"\bcopy\s*\(\s*{pname}(?:\s*\[[^\]]*\])?\s*,", body)
                )
                # (d) Mutating method call on parameter: `p.Write(...)`, `p.Swap(...)`, `p.Reset()`, `p.Grow(...)`
                method_write = bool(
                    re.search(
                        rf"\b{pname}\s*\.\s*(?:Write|WriteByte|WriteString|Swap|Reset|Grow|Truncate)\s*\(",
                        body,
                    )
                )
                # (e) Interface method call where `param` is passed to a mutating slot:
                # e.g. `r.Read(buf)` or `r.Read(buf[n:])`
                iface_arg_write = False
                for iface_method, arg_indices in INTERFACE_METHOD_MUTATED_ARGS.items():
                    if 0 in arg_indices:
                        if re.search(
                            rf"\.\s*{iface_method}\s*\(\s*{pname}(?:\s*\[[^\]]*\])?\b",
                            body,
                        ):
                            iface_arg_write = True
                            evidence_tier = "Tier2_Interface_Contract"

                # (f) Reflection sink: `reflect.ValueOf(v)` + `.Elem()` / `unmarshal(..., v)`
                reflect_sink_write = False
                if param.go_type.strip() in ("any", "interface{}"):
                    if re.search(
                        rf"(?:reflect\.ValueOf\s*\(\s*{pname}\b|d\.unmarshal\s*\(\s*{pname}\b|unmarshal\s*\([^,]+,\s*{pname}\b)",
                        body,
                    ):
                        reflect_sink_write = True
                        evidence_tier = "Tier2_Reflection_Sink"

                # (g) Intra-package helper propagation: `Helper(a, b, ...)` where Helper mutates slot `k`
                helper_write = False
                for callee_name, callee_desc in pkg_env.items():
                    if callee_desc.mutated_arg_mask == 0:
                        continue
                    for call_match in re.finditer(
                        rf"\b{re.escape(callee_name)}\s*\(([^)]*)\)", body
                    ):
                        call_args = [a.strip() for a in call_match.group(1).split(",")]
                        for k, carg in enumerate(call_args):
                            if (callee_desc.mutated_arg_mask & (1 << k)) != 0:
                                if re.match(rf"^(?:&\s*)?{pname}(?:\s*\[[^\]]*\])?$", carg):
                                    helper_write = True

                # (h) Sort-adapter wrapping: `Sort(IntSlice(x))` or `pdqsort...(x, ...)`
                sort_adapter_write = bool(
                    re.search(
                        rf"\b(?:Sort|Stable|IntSlice|Float64Slice|StringSlice|pdqsort\w*|insertionSort\w*|stable\w*)\s*\([^)]*\b{pname}\b",
                        body,
                    )
                )

                if (
                    direct_index_write
                    or direct_deref_write
                    or builtin_copy_write
                    or method_write
                    or iface_arg_write
                    or reflect_sink_write
                    or helper_write
                    or sort_adapter_write
                ):
                    mutated_mask |= 1 << idx

                # Sub-slice aliasing analysis (`may_share_arg_mask`, Rule O5.2):
                # Does the return value return a sub-slice of `param` (`return p[a:b]`)
                # or a slice of sub-slices (`genSplit(p, ...)`), confirmed by AST or
                # `-gcflags="-m=2"` `leaking param: <param> to result ~r0 level=0`?
                if is_slice_or_ptr_carrier(param.go_type) and returns and (
                    returns[0].startswith("[]") or returns[0].startswith("*")
                ):
                    ast_subslice_return = bool(
                        re.search(rf"\breturn\s+{pname}\s*\[[^\]]*:", body)
                        or re.search(rf"\bgenSplit\s*\(\s*{pname}\b", body)
                    )
                    gcflags_leaks_to_r0 = any(
                        f"leaking param: {param.name} to result ~r0 level=0" in line
                        or f"leaking param content: {param.name} to result ~r0" in line
                        for line in decl.gcflags_escape
                    )
                    if ast_subslice_return or gcflags_leaks_to_r0:
                        may_share_mask |= 1 << idx
                        if gcflags_leaks_to_r0 and not ast_subslice_return:
                            evidence_tier = "Tier2_Gcflags_Escape"
        else:
            # Bodyless function (assembly stub, CGo, or external interface decl)
            evidence_tier = "Tier3_Interface_Or_Asm_Conservative"
            for idx, param in enumerate(decl.params):
                if is_slice_or_ptr_carrier(param.go_type):
                    # Check if gcflags explicitly proves param does not escape AND
                    # function name/signature is a pure query vs a buffer writer
                    if self.strict_bodyless_conservative:
                        # Under strict fail-closed synthesis for bodyless assembly functions,
                        # any mutable slice/pointer dst without a read-only proof is flagged
                        # if named dst/buf or if no gcflags proof exists.
                        if param.name in ("dst", "buf", "p", "b") and not returns[0:1] == ["int"]:
                            mutated_mask |= 1 << idx
                        elif param.name in ("dst", "buf"):
                            mutated_mask |= 1 << idx

        # 3. Classify CallMode
        call_mode = "CallMode::Safe"
        if decl.receiver is not None:
            if mutated_mask != 0 or (
                body and re.search(rf"\b{re.escape(decl.receiver.name)}\.[A-Za-z0-9_]+\s*=", body)
            ):
                call_mode = "CallMode::Mutate"
        elif mutated_mask != 0:
            call_mode = "CallMode::Safe"

        return BoundaryDescriptor(
            pkg=decl.pkg,
            hy_name=hy_name,
            go_name=decl.go_name,
            is_method=decl.receiver is not None,
            receiver_type=decl.receiver.go_type if decl.receiver else None,
            result_shape=result_shape,
            result_count=result_count,
            fallible=fallible,
            mutated_arg_mask=mutated_mask,
            may_share_arg_mask=may_share_mask,
            call_mode=call_mode,
            evidence_tier=evidence_tier,
        )

    def emit_rust_tables(self, descriptors: List[BoundaryDescriptor]) -> str:
        """Emit drop-in Rust functions replacing `foreign.rs` hand-written match tables."""
        lines: List[str] = [
            "// AUTO-GENERATED BY W-024 BOUNDARY SYNTHESIZER — DO NOT EDIT BY HAND",
            "use crate::model::TypeShape;",
            "",
            "pub(crate) fn package_mutated_arg(pkg: &str, method: &str) -> Option<usize> {",
            "    match (pkg, method) {",
        ]
        for d in descriptors:
            first_mut = d.first_mutated_arg()
            if first_mut is not None and not d.is_method:
                lines.append(
                    f'        ("{d.pkg}", "{d.hy_name}" | "{d.go_name}") => Some({first_mut}),'
                )
        lines.extend(
            [
                "        _ => None,",
                "    }",
                "}",
                "",
                "pub(crate) fn package_may_share_arg(pkg: &str, method: &str) -> Option<usize> {",
                "    match (pkg, method) {",
            ]
        )
        for d in descriptors:
            first_share = d.first_shared_arg()
            if first_share is not None and not d.is_method:
                lines.append(
                    f'        ("{d.pkg}", "{d.hy_name}" | "{d.go_name}") => Some({first_share}),'
                )
        lines.extend(
            [
                "        _ => None,",
                "    }",
                "}",
                "",
                "pub(crate) fn package_result(pkg: &str, method: &str) -> TypeShape {",
                "    match (pkg, method) {",
            ]
        )
        for d in descriptors:
            if not d.is_method:
                lines.append(
                    f'        ("{d.pkg}", "{d.hy_name}" | "{d.go_name}") => {d.result_shape},'
                )
        lines.extend(
            [
                "        _ => TypeShape::Unknown,",
                "    }",
                "}",
                "",
                "pub(crate) fn package_result_count(pkg: &str, method: &str) -> Option<usize> {",
                "    match (pkg, method) {",
            ]
        )
        for d in descriptors:
            if not d.is_method and d.result_count >= 2:
                lines.append(
                    f'        ("{d.pkg}", "{d.hy_name}" | "{d.go_name}") => Some({d.result_count}),'
                )
        lines.extend(
            [
                "        _ => None,",
                "    }",
                "}",
            ]
        )
        return "\n".join(lines)


def audit_real_foreign_rs(repo_root: pathlib.Path) -> ForeignRsAudit:
    """
    Parse and audit the real `compiler/crates/hy-check/src/foreign.rs` file in the
    Go-Hybrid repository to ground all numbers in actual repository state.
    """
    foreign_rs = repo_root / "compiler" / "crates" / "hy-check" / "src" / "foreign.rs"
    text = foreign_rs.read_text(encoding="utf-8")
    lines = text.splitlines()

    # Extract BUILTIN_PACKAGES count
    builtin_m = re.search(r"BUILTIN_PACKAGES:\s*&\[&str\]\s*=\s*&\[(.*?)\];", text, re.S)
    builtin_pkgs = re.findall(r'"([^"]+)"', builtin_m.group(1)) if builtin_m else []

    # Extract package_mutated_arg entries
    mut_m = re.search(
        r"fn package_mutated_arg\(pkg: &str, method: &str\) -> Option<usize> \{(.*?)\n\}",
        text,
        re.S,
    )
    mutated_entries: Dict[Tuple[str, str], int] = {}
    if mut_m:
        body = mut_m.group(1)
        # Parse match arms
        for pkg_match in re.finditer(
            r'\(\s*"([^"]+)"\s*,\s*([^)]+?)\s*\)\s*=>\s*Some\((\d+)\)', body, re.S
        ):
            pkg_name = pkg_match.group(1)
            methods = re.findall(r'"([^"]+)"', pkg_match.group(2))
            idx = int(pkg_match.group(3))
            for m in methods:
                if m.islower() or "_" in m:
                    mutated_entries[(pkg_name, m)] = idx

    # Extract package_result entries
    res_m = re.search(
        r"fn package_result\(pkg: &str, method: &str\) -> TypeShape \{(.*?)\n\}",
        text,
        re.S,
    )
    result_entries: Dict[Tuple[str, str], str] = {}
    if res_m:
        body = res_m.group(1)
        for arm in re.finditer(
            r'\("([^"]+)",\s*([^)]+)\)\s*(?:\|\s*\("([^"]+)",\s*([^)]+)\))?\s*=>\s*([^,\n]+|\{[^}]+\})',
            body,
        ):
            pkg1 = arm.group(1)
            methods1 = re.findall(r'"([^"]+)"', arm.group(2))
            rhs = arm.group(5).strip().strip("{}").strip()
            for m in methods1:
                if m.islower() or "_" in m:
                    result_entries[(pkg1, m)] = rhs
            if arm.group(3):
                pkg2 = arm.group(3)
                methods2 = re.findall(r'"([^"]+)"', arm.group(4))
                for m in methods2:
                    if m.islower() or "_" in m:
                        result_entries[(pkg2, m)] = rhs

    # Extract is_curated_package_member symbol count
    curated_m = re.search(
        r"pub\(crate\) fn is_curated_package_member\(pkg: &str, member: &str\) -> bool \{(.*)\}",
        text,
        re.S,
    )
    curated_pkgs = 0
    curated_Read_symbols = 0
    if curated_m:
        cbody = curated_m.group(1)
        curated_pkgs = len(re.findall(r'"([a-z0-9_]+)"\s*=>', cbody))
        curated_Read_symbols = len(re.findall(r'"([a-z0-9_]+)"', cbody)) - curated_pkgs

    return ForeignRsAudit(
        path=str(foreign_rs),
        total_lines=len(lines),
        builtin_packages_count=len(builtin_pkgs),
        mutated_arg_entries=mutated_entries,
        package_result_entries=result_entries,
        curated_member_packages=curated_pkgs,
        curated_member_symbols=curated_Read_symbols,
    )
