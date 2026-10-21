# W-024 Spike: Zero-Annotation Foreign Boundary Descriptor Synthesis

**Kills sacred cows**:
1. `compiler/crates/hy-check/src/foreign.rs` (`1,280` lines of hand-maintained `match (pkg, method)` descriptor stubs flagged at `foreign.rs:3-16` as `TECH DEBT (post-MVP, tracked for the lead)`).
2. `SPEC.md` §13 M5 ("curated Go stdlib allowlist") and `GUARANTEES.md` Rows 6 & 7 ("Go stdlib beyond the curated surface" / "Third-party Go packages").
3. `foreign.rs:9-12`'s permissive `CallMode::Unknown` / missing-mutator fallback, which currently allows `HYB-E3006` (`const` mutation) and `O5.2` (`may_share` sub-slice aliasing) soundness holes inside the curated stdlib allowlist while causing `HYB-E3005` false-positive rejections at `task`/`chan` boundaries for 95%+ of curated value-returning functions.

## Reproducing the Spike (`< 10 ms`, zero dependencies)

```bash
python spikes/w024-foreign-boundary-synthesis/test_synthesis.py
```

## Empirical Results Against `compiler/crates/hy-check/src/foreign.rs`

| Metric | Hand-Written `foreign.rs` Baseline | W-024 Synthesizer (`synthesize.py`) |
| :--- | :--- | :--- |
| Source size | `1,280` lines (`23` package arms, `741` symbol strings) | `111` generated lines (`8.48 ms` for 52 functions) |
| Existing `package_mutated_arg` parity (`sort.*`, `io.read_full`, `io.read_at_least`, `io.copy_buffer`) | `10 / 10` (`100%`) | `10 / 10` (`100%` automatic recovery) |
| Curated `HYB-E3006` in-place mutators caught (`hex.decode`, `hex.encode`, `json.unmarshal`, `json.compact`, `json.html_escape`, `json.indent`) | **`0 / 6`** (`None` -> silent `const` write bypass!) | **`6 / 6`** (`Some(0)` / `Some(1)` synthesized automatically) |
| `O5.2` `may_share` sub-slice aliasing (`bytes.split`, `bytes.fields`, `bytes.trim_space` vs `bytes.clone`) | **`0 / 3`** (no `package_may_share_arg` table in `foreign.rs`) | **`3 / 3`** (`Some(0)` via AST + `-gcflags="-m=2"` `leaking param: s to result ~r0 level=0`, while `bytes.clone` is proven disjoint) |
| Curated pure stdlib functions returning exact `TypeShape` instead of `TypeShape::Unknown` (`HYB-E3005` false-reject under `O4.9`) | `11` functions total (`strconv.*`, `hex.*`, `filepath.*`, `path.*`, `url.*` all return `TypeShape::Unknown`) | `21 / 21` upgraded in test corpus (`TypeShape::Primitive`, `TypeShape::Str`, `TypeShape::Slice(Primitive)`) |
| `GUARANTEES.md` Row 11 (`atomic.load_pointer`) | `TypeShape::Unknown` (fail-closed) | `TypeShape::Unknown` (fail-closed preserved) |

## Falsifier Discoveries (`F1`, `F2`, `F3`)

- **Falsifier F1 (Why `-gcflags="-m=2"` alone is FALSIFIED for `mutated_arg`, and why AST/SSA store inspection is mandatory)**:
  A naive hypothesis is that Go's compiler escape analysis (`go build -gcflags="-m=2"`) can synthesize both `may_share` and `mutated_arg`. **F1 falsifies the `mutated_arg` half**: `sort.Ints(x []int)` and `hex.Decode(dst, src []byte)` both emit `x does not escape` / `dst does not escape` under `-gcflags="-m=2"`, because mutating a slice's backing array in place does not heap-escape the slice header. Thus:
  - `-gcflags="-m=2"` (`leaking param: s to result ~r0 level=0`) is exact for **`may_share`** (Rule `O5.2`),
  - **AST/SSA store inspection** (`p[i] = ...`, `copy(p, ...)`, `*p = ...`) is required for **`mutated_arg`** (Rule `T22` / `HYB-E3006`), and bodyless `.s` assembly functions (`body=None`, e.g., `cipher.XORKeyStream`) must fall back to a fail-closed **`Tier3_Interface_Or_Asm_Conservative`** tier.
- **Falsifier F2 (Interface Dispatch Indirection — `Tier2_Interface_Contract`)**:
  `io.ReadFull(r Reader, buf []byte)` does not index `buf[i]` directly; it calls `ReadAtLeast(r, buf, ...)`, which calls the interface method `r.Read(buf[n:])`. Without seeding `io.Reader.Read` -> `mutates arg 0` (`Tier2_Interface_Contract`), intraprocedural AST synthesis would miss `io.ReadFull` and `io.CopyBuffer`. Seeding the 2 standard I/O/sort mutating interface contracts (`Reader.Read`/`ReadAt`, `sort.Interface.Swap`) recovers 100% of `io.*` and `sort.*` transitively.
- **Falsifier F3 (Reflection Sink Opacity — `Tier2_Reflection_Sink`)**:
  `json.Unmarshal(data []byte, v any)` accepts `v any` (an empty interface box holding a caller pointer) and mutates the pointee via `reflect.ValueOf(v)`. Static parameter-type filtering that ignores `any` misses `json.Unmarshal`; tracking `any` parameters flowing into `reflect.ValueOf(v)` / `d.unmarshal(v)` (`Tier2_Reflection_Sink`) catches `mutated_arg = Some(1)`.
