# LFX Mentorship Application: Add Fuzzing and Robustness Testing to urunc

## Personal Details

<!-- Fill in your details -->

## Open Source Contributions

<!-- Fill in your contributions -->

## Project Overview

### What urunc does

urunc is a container runtime that executes unikernels (lightweight, single-address-space VMs) inside standard container workflows. It sits in the same position as runc in the container stack, but instead of spawning Linux processes, it launches unikernels on hypervisors like QEMU, Solo5/HVT, Solo5/SPT, Firecracker, Cloud Hypervisor, Hyperlight, and Hedge.

### The problem (Issue [#852](https://github.com/urunc-dev/urunc/issues/852))

urunc parses several untrusted inputs: the OCI `config.json`, the `com.urunc.unikernel.*` annotations, `urunc.json`, and resource values it converts into monitor arguments. Bad input should fail cleanly, but today nothing systematically tests edge cases. Issues [#818](https://github.com/urunc-dev/urunc/issues/818), [#819](https://github.com/urunc-dev/urunc/issues/819), [#820](https://github.com/urunc-dev/urunc/issues/820) show the kind of parsing and validation bugs that fuzzing would catch.

The issue references Go's built-in [fuzzing framework](https://go.dev/doc/security/fuzz/) and suggests [runc](https://github.com/opencontainers/runc) as inspiration.

### What I have already done

I wrote 12 native Go fuzz targets (`testing.F`) across 4 packages, ran them against over 20 million inputs, and found 1 bug and 1 architectural finding with property-based assertions (not just crash detection).

**Repository with fuzz targets and findings:** [github.com/Shreshtthh/urunc-fuzzing-proposal](https://github.com/Shreshtthh/urunc-fuzzing-proposal)

### Architecture: How data flows through urunc

Understanding where parsing happens requires tracing the full config pipeline:

```
bunny (image builder)
  | base64-encodes annotation values
  | stores them in OCI image manifest
  v
containerd
  | pulls image, stores in content store
  v
containerd-shim-urunc-v2
  | pkg/containerd-shim/containerd/annotations.go
  | fetchUruncAnnotations() reads annotations from manifest (line 92)
  | patchConfigJSON() writes them into config.json (line 160)
  | Values pass through AS-IS (still base64-encoded)
  v
urunc runtime
  | Reads config.json via OCI runtime-spec
  v
GetUnikernelConfig()  <-- pkg/unikontainers/config.go:83
  |-- Path A: getConfigFromSpec() then validate()
  |   If valid, return immediately
  |   Correct: bunny annotations are plaintext, no decode needed   
  |
  |
  |-- Path B (fallback): getConfigFromJSON() from urunc.json
  |   validate() then decode()
  |   Correct today: urunc.json values are base64-encoded
  |    Will need to change when encoding is deprecated
  v
Unikernel dispatch  <-- pkg/unikontainers/unikernels/
  | Selects unikraft.go, mewz.go, rumprun.go, etc.
  | Each implements types.Unikernel interface (types.go:20)
  | CommandString() builds guest command line
  | MonitorCli() / MonitorBlockCli() return monitor args
  v
VMM dispatch  <-- pkg/unikontainers/hypervisors/
  | Selects qemu.go, hvt.go, spt.go, firecracker.go, etc.
  | Each implements types.VMM interface (types.go:30)
  | BuildExecCmd() constructs the monitor argv
  | BUG: hvt/spt/qemu use strings.Split(" ") to build argv
  v
Network setup  <-- pkg/network/network.go
  | getTapIndex() counts TAP interfaces (line 65)
  | subnetMaskToCIDR() converts dotted-decimal mask (unikernels/utils.go:24)
  | BUG: no contiguity check on subnet masks
  v
Block device setup  <-- pkg/unikontainers/block.go
  | getMountInfo() parses /proc/self/mountinfo (line 59)
  v
Mount setup  <-- pkg/unikontainers/mount.go
  | mapVFSFlag() maps "ro","rw","nosuid" to mount(2) flags (line 212)
  v
syscall.Exec(vmm_binary, argv, env)
```

### Complete parsing surface inventory

Every function in urunc that processes external input, with exact file paths and line numbers:

**`pkg/unikontainers/config.go` (318 lines)**

| Function | Line | What it parses | Fuzz status |
|---|---|---|---|
| `validate()` | 68 | UnikernelConfig mandatory fields | Done (2.1M inputs, no bugs) |
| `GetUnikernelConfig()` | 83 | Bundle dir + OCI spec | Planned, Phase 2 |
| `getConfigFromSpec()` | 116 | spec.Annotations map | Done (1.7M inputs, no bugs) |
| `getConfigFromJSON()` | 158 | urunc.json file (JSON) | Planned, Phase 2 |
| `tryDecode()` | 200 | Arbitrary string, base64 attempt | Planned, Phase 1 |
| `decode()` | 210 | All UnikernelConfig fields, base64 | Done, BUG FOUND |

**`pkg/unikontainers/block.go` (452 lines)**

| Function | Line | What it parses | Fuzz status |
|---|---|---|---|
| `getMountInfo()` | 59 | `/proc/self/mountinfo` text | Planned, Phase 2 |
| `handleExplicitBlockImage()` | 173 | Block image + mountpoint strings | Planned, Phase 1 |

**`pkg/unikontainers/mount.go` (518 lines)**

| Function | Line | What it parses | Fuzz status |
|---|---|---|---|
| `mapVFSFlag()` | 212 | Single VFS mount option string | Planned, Phase 1 |

**`pkg/unikontainers/hypervisors/` (7 VMM backends)**

| Function | File | Line | Fuzz status |
|---|---|---|---|
| `HVT.BuildExecCmd()` | `hvt.go` | 155 | Planned, Phase 1 |
| `SPT.BuildExecCmd()` | `spt.go` | 67 | Planned, Phase 1 |
| `Qemu.BuildExecCmd()` | `qemu.go` | 63 | Planned, Phase 1 |
| `CloudHypervisor.BuildExecCmd()` | `cloud_hypervisor.go` | 67 | Planned, Phase 1 |
| `Firecracker.BuildExecCmd()` | `firecracker.go` | 104 | Planned, Phase 1 |
| `Hyperlight.BuildExecCmd()` | `hyperlight.go` | 65 | Planned, Phase 1 |
| `Hedge.BuildExecCmd()` | `hedge.go` | 58 | Planned, Phase 1 |
| `BytesToStringMB()` | `utils.go` | 55 | Done (2.5M inputs) |
| `bytesToMiB()` | `utils.go` | 45 | Done (3.3M inputs) |
| `bytesToMB()` | `utils.go` | 50 | Done (2.4M inputs) |
| `appendNonEmpty()` | `utils.go` | 38 | Done (2.6M inputs) |

**`pkg/unikontainers/unikernels/` (7 unikernel types)**

| Function | File | Line | Fuzz status |
|---|---|---|---|
| `subnetMaskToCIDR()` | `utils.go` | 24 | Done, BUG FOUND |
| `Unikraft.CommandString()` | `unikraft.go` | 53 | Planned, Phase 1 |
| `Rumprun.CommandString()` | `rumprun.go` | varies | Planned, Phase 1 |

**`pkg/network/network.go` (464 lines)**

| Function | Line | What it parses | Fuzz status |
|---|---|---|---|
| `getTapIndex()` | 65 | System network interfaces | Planned, Phase 2 |

**`pkg/containerd-shim/containerd/annotations.go` (236 lines)**

| Function | Line | What it parses | Fuzz status |
|---|---|---|---|
| `patchConfigJSON()` | 160 | OCI spec JSON + annotation map | Planned, Phase 2 |

**`pkg/unikontainers/ipc_message.go`**

| Function | What it parses | Fuzz status |
|---|---|---|
| `bytemsg.Serialize/Deserialize` | Netlink byte messages | Done (4.4M inputs) |
| `int32msg.Serialize/Deserialize` | Netlink int32 messages | Done (4.4M inputs) |

### Bugs found

#### Bug 1: `decode()` silently corrupts plaintext annotation values

**File:** `pkg/unikontainers/config.go:210`
**Severity:** High. Causes silent misconfiguration with no error returned.

`decode()` unconditionally base64-decodes every UnikernelConfig field. Plaintext values that happen to be valid base64 are silently decoded to garbage bytes:

| Input (plaintext) | After decode() | Error returned |
|---|---|---|
| `"qemu"` | `"\xa9\xe9\xae"` (garbage) | `nil` |
| `"unikraft"` | `"\xbax\xa4\xad\xa7\xed"` (garbage) | `nil` |
| `"mewz"` | `"\x99\xec3"` (garbage) | `nil` |
| `"\r"` (carriage return) | `""` (empty string) | `nil` |

**Root cause:** The base64 encoding originates in bima (the image builder). The containerd shim (`annotations.go:92`) passes encoded values through to `config.json`. When urunc runs without the shim (e.g., direct `ctr run --annotation`), annotations arrive as plaintext. `decode()` on line 210 runs unconditionally and corrupts them. The TODO on line 86 acknowledges this gap: *"in case of urunc executed without shim, the annotations would remain encoded."*

**Reproduction:**
```bash
go test -run='^FuzzConfigDecode$' -fuzz='^FuzzConfigDecode$' -fuzztime=10s ./pkg/unikontainers/
```

**Proposed fix direction:** A protocol-level fix is ideal: add a `com.urunc.unikernel.encoding: base64` annotation in bima, and only decode when present. As a transitional fallback, a try-decode-then-validate heuristic can check whether the decoded bytes are valid UTF-8 (the garbage from accidental base64 matches like `"qemu"` to `"\xa9\xe9\xae"` is not valid UTF-8). This needs discussion with maintainers since edge cases exist.

#### Bug 2: `subnetMaskToCIDR()` accepts non-contiguous masks

**File:** `pkg/unikontainers/unikernels/utils.go:24`
**Severity:** Medium. Causes silent network misconfiguration.
**Related:** [#909](https://github.com/urunc-dev/urunc/issues/909)

The function counts all `1` bits without checking contiguity. A valid subnet mask requires all `1` bits to be contiguous from the left.

| Input | Returned | Correct | Binary representation |
|---|---|---|---|
| `"255.0.255.0"` | `16` | Error | `11111111.00000000.11111111.00000000` |
| `"128.0.128.0"` | `2` | Error | `10000000.00000000.10000000.00000000` |

**Proposed fix:**
```go
maskVal := uint32(parts[0])<<24 | uint32(parts[1])<<16 | uint32(parts[2])<<8 | uint32(parts[3])
inverted := ^maskVal & 0xFFFFFFFF
if maskVal != 0 && maskVal != 0xFFFFFFFF && (inverted&(inverted+1)) != 0 {
    return 0, fmt.Errorf("non-contiguous subnet mask: %s", subnetMask)
}
```

The check works because a valid mask's inverted form (e.g., `0x00FFFFFF` for `/8`) is always a contiguous block of trailing 1s, meaning `(inverted & (inverted + 1)) == 0`.

### Detailed implementation plan (12 weeks)

#### Phase 1: Fuzz pure functions without refactoring (Weeks 1 to 3)

**Week 1: Fuzz all 7 `BuildExecCmd()` implementations**

Three backends (`hvt.go:170`, `spt.go:82`, `qemu.go:145`) use `strings.Split(cmdString, " ")` to build argv. This breaks when any input value contains a space (e.g., a unikernel path like `/rootfs/my kernel`).

To fuzz `BuildExecCmd()`, I need a mock that implements `types.Unikernel` (defined in `types.go:20`). The interface requires 7 methods: `Init()`, `CommandString()`, `SupportsBlock()`, `SupportsFS()`, `MonitorNetCli()`, `MonitorBlockCli()`, and `MonitorCli()`. Here is the exact mock and fuzz target:

```go
type mockUnikernel struct {
    netCli   string
    blockCli []types.MonitorBlockArgs
    monCli   types.MonitorCliArgs
}

func (m *mockUnikernel) Init(_ types.UnikernelParams) error     { return nil }
func (m *mockUnikernel) CommandString() (string, error)         { return "", nil }
func (m *mockUnikernel) SupportsBlock() bool                    { return true }
func (m *mockUnikernel) SupportsFS(_ string) bool               { return true }
func (m *mockUnikernel) MonitorNetCli(_, _ string) string       { return m.netCli }
func (m *mockUnikernel) MonitorBlockCli() []types.MonitorBlockArgs { return m.blockCli }
func (m *mockUnikernel) MonitorCli() types.MonitorCliArgs       { return m.monCli }

func FuzzHVTBuildExecCmd(f *testing.F) {
    f.Add("/rootfs/kernel", "init=/bin/sh", "/dev/sda", "rootfs", "")
    f.Add("/rootfs/my kernel", "arg with spaces", "", "", "")

    f.Fuzz(func(t *testing.T, unikernelPath, command, blockPath, blockID, otherArgs string) {
        h := &HVT{binaryPath: "/usr/bin/solo5-hvt"}
        args := types.ExecArgs{
            UnikernelPath: unikernelPath,
            Command:       command,
            MemSizeB:      256 * 1000 * 1000,
        }
        ukernel := &mockUnikernel{
            blockCli: []types.MonitorBlockArgs{{ID: blockID, Path: blockPath}},
            monCli:   types.MonitorCliArgs{OtherArgs: otherArgs},
        }
        cmdArgs, err := h.BuildExecCmd(args, ukernel)
        if err != nil {
            return
        }
        // Property: no empty argv elements
        for i, arg := range cmdArgs {
            if arg == "" {
                t.Errorf("empty argv at index %d: %v", i, cmdArgs)
            }
        }
        // Property: UnikernelPath preserved as single element
        if unikernelPath != "" {
            found := false
            for _, a := range cmdArgs {
                if a == unikernelPath { found = true; break }
            }
            if !found {
                t.Errorf("UnikernelPath %q split across argv: %v", unikernelPath, cmdArgs)
            }
        }
    })
}
```

`hyperlight.go` uses `append()` instead of string concatenation, so it should pass. This contrast is itself a finding: the newer backend got it right, but the older ones did not.

**Week 2: Fuzz `mapVFSFlag()`, `handleExplicitBlockImage()`, `tryDecode()`**

`mapVFSFlag()` in `mount.go:212` is a pure lookup from string to mount(2) flag. It maps 28 options (`"ro"`, `"rw"`, `"nosuid"`, `"suid"`, etc.) to their corresponding `unix.MS_*` constants. Fuzz properties: every accepted input must produce a nonzero flag, and the function must be idempotent.

`handleExplicitBlockImage()` in `block.go:173` validates block device annotations. Fuzz properties: empty `blockImg` must return empty params, non-empty `blockImg` with empty `mountPoint` must return an error.

`tryDecode()` in `config.go:200` has the same base64 ambiguity as `decode()`. Fuzz with round-trip property.

**Week 3: Fix bugs and fuzz unikernel `CommandString()` methods**

Submit PRs for both bugs found:
- `decode()` fix with fuzz test as regression guard
- `subnetMaskToCIDR()` contiguity check with fuzz test

Fuzz `Unikraft.CommandString()` and `Rumprun.CommandString()`. These build the guest command line from struct fields. Property: output must not contain NUL bytes.

#### Phase 2: Refactor I/O-bound code for testability (Weeks 4 to 7)

**Risk mitigation:** Before opening any refactoring PRs, I will first open an architectural discussion issue on each proposed change (e.g., "Proposal: extract parseMountInfoEntry() from getMountInfo() for testability") to get maintainer buy-in on the exact function signatures and scope. This avoids wasted work on PRs that might be rejected.

**Fallback plan:** If the maintainers prefer not to refactor production code paths, I will fuzz these functions using `t.TempDir()` to create temporary files with crafted content, and pass real file paths to the existing functions. This is slower than fuzzing pure parsing functions and tests integration rather than parsing in isolation, but it still provides coverage without requiring any production code changes.

**Week 4 to 5: Refactor `getMountInfo()`** (`block.go:59`)

Currently reads `/proc/self/mountinfo` directly. The parsing logic on lines 72 to 109 is tightly coupled to the file handle.

Refactoring plan: extract a `parseMountInfoEntry(line string)` function that parses a single mountinfo line and returns structured data. The parent function accepts an `io.Reader` instead of hardcoding the file path. All existing tests will continue to pass with zero behavior change, since the refactoring only splits the function without altering logic:

```go
// Before (untestable):
func getMountInfo(path string) (types.BlockDevParams, error) {
    file, err := os.Open("/proc/self/mountinfo")  // hardcoded
    // 50 lines of parsing interleaved with file I/O
}

// After (testable):
func parseMountInfoEntry(line string) (mountPoint, fsType, source, options string, err error) {
    parts := strings.Split(line, " - ")
    if len(parts) != 2 {
        return "", "", "", "", fmt.Errorf("invalid mountinfo line")
    }
    // ... pure parsing, no I/O
}

func findMountForPath(reader io.Reader, path string) (types.BlockDevParams, error) {
    scanner := bufio.NewScanner(reader)
    // ... calls parseMountInfoEntry() per line
}
```

In tests: `findMountForPath(strings.NewReader("fake mountinfo"), "/mnt")`.
In production: `findMountForPath(os.Open("/proc/self/mountinfo"), path)`.

This follows runc's approach: runc's `libcontainer/specconv` separates OCI spec conversion (pure parsing) from actual container setup (syscalls), making the parsing layer fuzzable.

**Week 6: Refactor `patchConfigJSON()`** (`containerd/annotations.go:160`)

Extract the pure spec-patching logic:

```go
// patchSpec merges annotations into an OCI spec, preserving existing keys.
func patchSpec(spec *runtimespec.Spec, annotations map[string]string) {
    if spec.Annotations == nil {
        spec.Annotations = make(map[string]string)
    }
    for k, v := range annotations {
        if _, exists := spec.Annotations[k]; !exists {
            spec.Annotations[k] = v
        }
    }
}
```

Fuzz property: existing annotation keys are never overwritten.

**Week 7: Integration fuzz for `GetUnikernelConfig()`** (`config.go:83`)

Fuzz the full pipeline with a temp directory containing a crafted `config.json` and `urunc.json`. This tests the interaction between `getConfigFromSpec()`, `validate()`, `getConfigFromJSON()`, and `decode()` together.

#### Phase 3: Continuous fuzzing infrastructure (Weeks 8 to 10)

Set up [OSS-Fuzz](https://github.com/google/oss-fuzz) for urunc, following [runc's integration](https://github.com/google/oss-fuzz/tree/master/projects/runc).

**Dockerfile:**
```dockerfile
FROM gcr.io/oss-fuzz-base/base-builder-go
RUN git clone --depth 1 https://github.com/urunc-dev/urunc $SRC/urunc
COPY build.sh $SRC/
WORKDIR $SRC/urunc
```

**build.sh:**
```bash
#!/bin/bash -eu
cd $SRC/urunc

compile_native_go_fuzzer github.com/urunc-dev/urunc/pkg/unikontainers \
    FuzzConfigDecode fuzz_config_decode
compile_native_go_fuzzer github.com/urunc-dev/urunc/pkg/unikontainers \
    FuzzConfigJSONRoundTrip fuzz_config_json_roundtrip
compile_native_go_fuzzer github.com/urunc-dev/urunc/pkg/unikontainers/hypervisors \
    FuzzHVTBuildExecCmd fuzz_hvt_build_exec_cmd
compile_native_go_fuzzer github.com/urunc-dev/urunc/pkg/unikontainers/unikernels \
    FuzzSubnetMaskToCIDR fuzz_subnet_mask_to_cidr
compile_native_go_fuzzer github.com/urunc-dev/urunc/pkg/unikontainers \
    FuzzParseMountInfoEntry fuzz_parse_mount_info
compile_native_go_fuzzer github.com/urunc-dev/urunc/pkg/unikontainers \
    FuzzMapVFSFlag fuzz_map_vfs_flag
# Additional targets added during Phase 1 and 2
```

**project.yaml:**
```yaml
homepage: "https://github.com/urunc-dev/urunc"
main_repo: "https://github.com/urunc-dev/urunc"
language: go
fuzzing_engines:
  - libfuzzer
sanitizers:
  - address
```

`compile_native_go_fuzzer` is a script provided by the OSS-Fuzz infrastructure that wraps Go's native `testing.F` fuzz targets into libFuzzer-compatible binaries. It locates the fuzz function, verifies its signature matches `func FuzzXxx(f *testing.F)`, and compiles it using the `go-118-fuzz-build` tool.

If OSS-Fuzz registration takes longer than expected, I will implement [ClusterFuzzLite](https://google.github.io/clusterfuzzlite/) as a GitHub Action. ClusterFuzzLite runs on every PR with no external registration needed.

#### Phase 4: CI integration and documentation (Weeks 11 to 12)

**CI integration:** The current `unit_test.yml` workflow calls `make unittest`, which runs `test_unikontainers`, `test_metrics`, `test_network`, `test_hypervisors`, and `test_unikernels` Makefile targets. I will add:

```yaml
      - name: Run fuzz regression tests
        run: |
          go test -run='^Fuzz' -fuzztime=1x ./pkg/unikontainers/...
          go test -run='^Fuzz' -fuzztime=1x ./pkg/unikontainers/hypervisors/...
          go test -run='^Fuzz' -fuzztime=1x ./pkg/unikontainers/unikernels/...
```

The `-fuzztime=1x` flag runs each fuzz target against its saved corpus entries only (no mutations), so it takes seconds and catches regressions without the cost of full fuzzing.

**Makefile target:**
```makefile
## fuzztest Run fuzz regression tests (seed corpus only)
.PHONY: fuzztest
fuzztest:
	@echo "Running fuzz regression tests"
	@$(GO) test -run='^Fuzz' -fuzztime=1x ./pkg/unikontainers/... -v
	@$(GO) test -run='^Fuzz' -fuzztime=1x ./pkg/unikontainers/hypervisors/... -v
	@$(GO) test -run='^Fuzz' -fuzztime=1x ./pkg/unikontainers/unikernels/... -v
```

**Corpus management policy:** Only two types of files will be committed to the urunc repository:
1. **Hand-crafted seed corpus entries** (5 to 10 per fuzz target): representative real-world inputs and known edge cases. These are small text files, typically under 1KB each.
2. **Crash reproducers**: when a fuzzer finds a bug, Go saves the failing input to `testdata/fuzz/FuncName/`. These are tiny and must be committed to prevent regressions.

The continuously generated corpus from `-fuzztime` runs (which can grow to thousands of files) will NOT be committed to the repository. OSS-Fuzz manages its own corpus externally on Google's infrastructure.

**Documentation deliverables:**
- Contributing guide: how to write a fuzz target for urunc (naming convention, property selection, seed corpus curation)
- Fuzzing playbook: how to interpret fuzzer crashes, triage findings, and file bug reports
- Corpus management: when to check in `testdata/fuzz/` entries, how to update seeds

### Week-by-week deliverable schedule

| Week | Deliverable | Review artifact |
|---|---|---|
| 1 | Fuzz targets for all 7 BuildExecCmd() implementations | PR with mock Unikernel + tests |
| 2 | Fuzz targets for mapVFSFlag(), handleExplicitBlockImage(), tryDecode() | PR |
| 3 | Bug-fix PRs for decode() and subnetMaskToCIDR(), fuzz CommandString() | 2 fix PRs + 1 test PR |
| 4 | Open architecture issues for Phase 2 refactors, begin getMountInfo() refactor | Issue + Refactor PR |
| 5 | Refactor patchConfigJSON(): extract patchSpec() | Refactor PR |
| 6 | Fuzz targets for parseMountInfoEntry(), patchSpec(), findMountForPath() | PR |
| 7 | Integration fuzz for GetUnikernelConfig() with temp filesystem | PR |
| 8 | Draft OSS-Fuzz config (Dockerfile, build.sh, project.yaml) | PR to google/oss-fuzz |
| 9 | Test OSS-Fuzz locally with `python infra/helper.py build_fuzzers` | Test report |
| 10 | Submit OSS-Fuzz PR, or implement ClusterFuzzLite as fallback | PR |
| 11 | CI integration: fuzz regression in unit_test.yml + Makefile target | PR to urunc |
| 12 | Documentation: contributing guide, fuzzing playbook, corpus management | Docs PR |

### Success metrics

I will track statement coverage in `pkg/unikontainers` and `pkg/network` using `go test -coverprofile` before and after each phase, and report the delta in my weekly updates. Some code paths (e.g., KVM setup, block device ioctls, TAP interface creation) require real hardware and cannot be reached by unit-level fuzzing, so I will not promise a specific coverage percentage. Instead, I will report the coverage of fuzzable parsing functions specifically, giving an honest picture of what the fuzzing suite exercises.

## Results For The urunc Community

This mentorship will deliver:

1. **Immediate safety improvements.** Two bugs fixed with regression-guarding fuzz tests. The `decode()` fix alone resolves a class of silent misconfigurations that affect every user running urunc without the containerd shim.

2. **A comprehensive fuzz test suite.** 20+ fuzz targets covering every input-parsing function in urunc. These run as regular `go test` commands, so any contributor can use them without extra tooling.

3. **Continuous fuzzing via OSS-Fuzz.** Once registered, Google's infrastructure runs the fuzz targets 24/7 with address sanitizer enabled. Crashes are automatically reported to the maintainers. This is the same infrastructure that protects runc, containerd, and other CNCF projects.

4. **CI regression testing.** Every PR automatically runs fuzz seed corpus entries. This catches regressions in seconds without the cost of full fuzzing, integrated into the existing `unit_test.yml` workflow.

5. **Improved code testability.** The Phase 2 refactoring (extracting pure parsing functions from I/O-bound code) benefits all future testing, not just fuzzing. Functions like `parseMountInfoEntry()` and `patchSpec()` become independently testable with standard unit tests.

6. **Documentation for future contributors.** A fuzzing contributing guide, crash triage playbook, and corpus management docs ensure the fuzzing infrastructure remains maintainable after the mentorship ends.

7. **Long-term engagement.** After the mentorship, I plan to continue maintaining the fuzz targets, triaging OSS-Fuzz reports, and reviewing fuzzing-related PRs. I also plan to write a blog post documenting the process and findings, which can serve as a reference for other CNCF projects looking to add fuzzing.

## Personal Inspiration

<!-- Fill in: why this project, why open source, why unikernels/containers -->

## Commitments

<!-- Fill in the first two lines below -->
**Time commitment:** <!-- e.g., "I commit to working X hours per week for the 12-week duration." State if full-time or part-time, and mention any classes/work. -->

**Timezone:** <!-- e.g., IST (UTC+5:30). Mention overlap hours with EU timezones if applicable. -->

**Communication cadence:**
- Async daily updates on Slack/Discord summarizing what I worked on, what's blocked, and what's next
- Weekly summary report posted as a GitHub comment on the tracking issue, including coverage metrics and links to PRs submitted that week
- Available for a 30-minute weekly video sync with my mentor at a mutually convenient time
- All PRs will include a clear description of the change, the property being tested, and reproduction instructions for any bugs found

**LLM disclosure:** I used AI assistance (Gemini, via Antigravity) to navigate the codebase and build test harnesses. I have verified and understand all findings myself. Every file path, line number, and code sample in this proposal was cross-referenced against the actual urunc source code.
