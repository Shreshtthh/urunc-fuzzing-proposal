# urunc Fuzzing & Robustness Testing — LFX Term 3 Proposal

## Summary

I wrote **12 native Go fuzz targets** (`testing.F`) across 4 packages in urunc, testing config parsing, hypervisor resource conversion, subnet mask validation, and IPC serialization. The fuzzers found **2 distinct bugs** using property-based assertions, not just crash detection. This repo contains my fuzz targets, findings, and a detailed technical plan for the 12-week mentorship.

**Fork with fuzz tests:** [github.com/Shreshtthh/urunc/tree/fuzzing-initial-targets](https://github.com/Shreshtthh/urunc/tree/fuzzing-initial-targets)

---

## Findings

### Bug 1: `decode()` Silently Corrupts Plaintext Annotation Values

**File:** [`config.go:210`](https://github.com/urunc-dev/urunc/blob/main/pkg/unikontainers/config.go#L210)

`decode()` unconditionally base64-decodes every `UnikernelConfig` field. Plaintext values that happen to be valid base64 (`"qemu"`, `"unikraft"`, `"mewz"`) are silently decoded to garbage bytes with no error returned.

| Input | After `decode()` | Error |
|---|---|---|
| `"qemu"` | `"\xa9\xe9\xae"` | `nil` |
| `"unikraft"` | `"\xbax\xa4\xad\xa7\xed"` | `nil` |
| `"\r"` | `""` | `nil` |

**Root cause analysis:** I traced the full config pipeline to understand WHY `decode()` exists:

1. **Encoding origin:** The base64 encoding happens in **bima** (the unikernel image builder), NOT in the urunc shim. When bima packages a unikernel image, it stores annotation values as base64 in the OCI image manifest.

2. **Shim path:** The containerd shim ([`annotations.go`](https://github.com/urunc-dev/urunc/blob/main/pkg/containerd-shim/containerd/annotations.go)) fetches annotations from the image manifest and patches them into `config.json` — passing through base64-encoded values as-is.

3. **Runtime path:** `GetUnikernelConfig()` ([`config.go:83`](https://github.com/urunc-dev/urunc/blob/main/pkg/unikontainers/config.go#L83)) first tries `getConfigFromSpec()` (annotations from `config.json`). If validation fails, it falls back to `urunc.json` and calls `decode()` on line 109.

4. **The bug:** The existing `TODO` comment on line 86 acknowledges this: *"in case of urunc executed without shim, the annotations would remain encoded"*. But the reverse is also true — when annotations arrive already decoded (e.g., set directly via `ctr run --annotation`), `decode()` corrupts them.

**Proposed fix:** The cleanest approach is a **try-decode-then-validate** pattern:
```go
func (c *UnikernelConfig) decode() error {
    for _, field := range c.allFields() {
        decoded, err := base64.StdEncoding.DecodeString(*field)
        if err != nil {
            // Not valid base64 — keep the original value (it's plaintext)
            continue
        }
        // Check if the decoded value is valid UTF-8 and looks like a real value
        // (not garbage from accidental base64 match)
        if utf8.Valid(decoded) {
            *field = string(decoded)
        }
        // If decoded bytes aren't valid UTF-8, keep original — it wasn't
        // actually base64-encoded, just coincidentally valid base64 syntax
    }
    return nil
}
```
This requires discussion with maintainers — the UTF-8 heuristic handles most cases (`"qemu"` → `"\xa9\xe9\xae"` is not valid UTF-8), but may not cover all edge cases.

### Bug 2: `subnetMaskToCIDR()` Accepts Non-Contiguous Masks

**File:** [`unikernels/utils.go:24`](https://github.com/urunc-dev/urunc/blob/main/pkg/unikontainers/unikernels/utils.go#L24) — Related: [#909](https://github.com/urunc-dev/urunc/issues/909)

The function counts all `1` bits without checking contiguity. `"255.0.255.0"` returns `/16` instead of an error.

**Proposed fix:** Add contiguity check after parsing:
```go
maskVal := uint32(parts[0])<<24 | uint32(parts[1])<<16 | uint32(parts[2])<<8 | uint32(parts[3])
inverted := ^maskVal & 0xFFFFFFFF
if maskVal != 0 && maskVal != 0xFFFFFFFF && (inverted&(inverted+1)) != 0 {
    return 0, fmt.Errorf("non-contiguous subnet mask: %s", subnetMask)
}
```

---

## Parsing Function Coverage Map

Every function in urunc that parses external input:

###  Covered by my fuzz targets (10 functions)

| Function | File | Fuzz Target | Result |
|---|---|---|---|
| `decode()` | `config.go:210` | `FuzzConfigDecode`, `FuzzConfigDecodeAllFields` |  Bug |
| `validate()` | `config.go:68` | `FuzzConfigValidate` |  2.1M inputs |
| `getConfigFromSpec()` | `config.go:116` | `FuzzGetConfigFromSpec` |  1.7M inputs |
| JSON unmarshal | `config.go:179` | `FuzzConfigJSONRoundTrip` |  2.1M inputs |
| `subnetMaskToCIDR()` | `unikernels/utils.go:24` | `FuzzSubnetMaskToCIDR`, `FuzzSubnetMaskToCIDRContiguity` |  Bug |
| `bytesToMiB()` | `hypervisors/utils.go:45` | `FuzzBytesToMiB` |  3.3M inputs |
| `bytesToMB()` | `hypervisors/utils.go:50` | `FuzzBytesToMB` |  2.4M inputs |
| `BytesToStringMB()` | `hypervisors/utils.go:55` | `FuzzBytesToStringMB` |  2.5M inputs |
| `appendNonEmpty()` | `hypervisors/utils.go:38` | `FuzzAppendNonEmpty` |  2.6M inputs |
| `bytemsg/int32msg.Serialize()` | `ipc_message.go` | `FuzzBytemsgSerialize`, `FuzzInt32msgSerialize` |  4.4M inputs |

### Not yet covered — planned for mentorship

| Function | File | Why It Needs Fuzz Coverage | Refactoring Required? |
|---|---|---|---|
| `BuildExecCmd()` | `hvt.go:155`, `spt.go:67`, `qemu.go:63` | Uses `strings.Split(cmd, " ")` — breaks on spaces in paths | No — already unit-testable via `types.VMM` interface |
| `BuildExecCmd()` | `firecracker.go:104`, `cloud_hypervisor.go:67` | Same arg-building pattern | No |
| `GetUnikernelConfig()` | `config.go:83` | Full pipeline integration test | Yes — needs mock `specs.Spec` and temp filesystem |
| `getMountInfo()` | `block.go:67` | Parses `/proc/self/mountinfo` text | Yes — needs `io.Reader` parameter instead of hardcoded path |
| `patchConfigJSON()` | `containerd/annotations.go:160` | JSON read → unmarshal → modify → write | Yes — needs filesystem abstraction |
| `fetchUruncAnnotations()` | `containerd/annotations.go:92` | Containerd gRPC client interaction | Yes — needs mock `contentapi.ContentClient` |
| `getTapIndex()` | `network/network.go:65` | Counts system TAP interfaces | Yes — needs mock `net.Interfaces()` |
| `tryDecode()` | `config.go:200` | Same base64 ambiguity as `decode()` | No |

---

## Proposed Plan (12 weeks)

### Phase 1: Expand Native Fuzz Coverage (Weeks 1–3)

**Goal:** Fuzz all functions that don't require refactoring.

- Fuzz all 5 `BuildExecCmd()` implementations. Each hypervisor backend (`hvt.go`, `spt.go`, `qemu.go`, `firecracker.go`, `cloud_hypervisor.go`) implements the `types.VMM` interface, so we can instantiate them directly in tests without mocking. Property: no empty argv elements, no split tokens from values containing spaces.
- Fuzz `tryDecode()` — same round-trip property as `decode()`.
- Fix `decode()` silent corruption — implement try-decode-then-validate with UTF-8 check, submit PR with fuzz test as regression guard.
- Fix `subnetMaskToCIDR()` contiguity — add bitwise check, submit PR.
- Curate seed corpus from real-world `urunc.json` files and OCI annotation examples in the urunc docs.

### Phase 2: Refactor I/O-Bound Code for Testability (Weeks 4–7)

**Goal:** Make currently-untestable parsing functions fuzzable.

Specific refactoring plan:

| Function | Current Issue | Proposed Refactoring |
|---|---|---|
| `getMountInfo()` | Reads `/proc/self/mountinfo` directly | Extract a `parseMountInfoLine(line string)` function; fuzz that |
| `GetUnikernelConfig()` | Needs filesystem + spec | Accept `io.Reader` for JSON source; test full pipeline with in-memory data |
| `patchConfigJSON()` | Reads/writes filesystem | Extract `patchSpec(spec *Spec, annotations map[string]string)` function; fuzz that |
| `getTapIndex()` | Calls `net.Interfaces()` | Accept interface list as parameter |

This approach follows runc's pattern: runc's `libcontainer/specconv` separates OCI spec → libcontainer config conversion from actual container setup, making it fuzzable. We apply the same principle to urunc.

### Phase 3: Continuous Fuzzing Infrastructure (Weeks 8–10)

**Goal:** Set up OSS-Fuzz for urunc, following [runc's OSS-Fuzz integration](https://github.com/google/oss-fuzz/tree/master/projects/runc).

Draft configuration:

**`Dockerfile`:**
```dockerfile
FROM gcr.io/oss-fuzz-base/base-builder-go

RUN git clone --depth 1 https://github.com/urunc-dev/urunc
COPY build.sh $SRC/
WORKDIR $SRC/urunc
```

**`build.sh`:**
```bash
#!/bin/bash -eu

# Compile all native Go fuzz targets
compile_native_go_fuzzer github.com/urunc-dev/urunc/pkg/unikontainers FuzzConfigDecode fuzz_config_decode
compile_native_go_fuzzer github.com/urunc-dev/urunc/pkg/unikontainers FuzzConfigJSONRoundTrip fuzz_config_json
compile_native_go_fuzzer github.com/urunc-dev/urunc/pkg/unikontainers/unikernels FuzzSubnetMaskToCIDR fuzz_subnet_mask
compile_native_go_fuzzer github.com/urunc-dev/urunc/pkg/unikontainers/hypervisors FuzzBytesToStringMB fuzz_bytes_to_string
# ... additional targets added during Phase 1-2
```

**`project.yaml`:**
```yaml
homepage: "https://github.com/urunc-dev/urunc"
main_repo: "https://github.com/urunc-dev/urunc"
language: go
fuzzing_engines:
  - libfuzzer
sanitizers:
  - address
```

Alternative: If OSS-Fuzz registration takes too long, implement **ClusterFuzzLite** as a GitHub Action in the urunc repo (runs on every PR, no external registration needed).

### Phase 4: CI Integration & Documentation (Weeks 11–12)

**Goal:** Make fuzzing a permanent part of urunc's development workflow.

**CI integration** — add to `.github/workflows/unit_test.yml`:
```yaml
    - name: Run fuzz regression tests
      run: |
        # Run each fuzz target against its saved corpus (no mutations)
        # This catches regressions without the time cost of full fuzzing
        go test -run='^Fuzz' ./pkg/unikontainers/...
        go test -run='^Fuzz' ./pkg/unikontainers/hypervisors/...
        go test -run='^Fuzz' ./pkg/unikontainers/unikernels/...
```

**Documentation:**
- Contributing guide: how to write a fuzz target for urunc (naming convention, property selection, seed corpus)
- Playbook: how to interpret fuzzer crashes and file bug reports
- Corpus management: when to check in testdata, how to update seeds

---

## About Me



**LLM disclosure:** I used AI assistance to navigate the codebase and build test harnesses. I verified and understand all findings myself.
