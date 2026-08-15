# Bug Reports

## Bug 1: `decode()` Silently Corrupts Plaintext Annotation Values

**File:** `pkg/unikontainers/config.go:210`  
**Severity:** High — causes silent misconfiguration, opaque downstream failures  
**Related:** #818, #819, #820, #876

### Description

`UnikernelConfig.decode()` unconditionally runs `base64.StdEncoding.DecodeString()` on every config field. It assumes all values are base64-encoded. However, some plaintext strings happen to be **valid base64 by coincidence** (length is a multiple of 4, only uses characters from `[A-Za-z0-9+/=]`). Go's base64 decoder accepts them without error, producing garbage bytes.

### Affected Values

| Input (plaintext) | After `decode()` | Error returned |
|---|---|---|
| `"qemu"` | `"\xa9\xe9\xae"` (garbage) | `nil` |
| `"unikraft"` | `"\xbax\xa4\xad\xa7\xed"` (garbage) | `nil` |
| `"mewz"` | `"\x99\xec3"` (garbage) | `nil` |
| `"\r"` (carriage return) | `""` (empty) | `nil` |
| `"001="` | `"\xd3M"` (garbage) | `nil` |

Other hypervisor names (`hvt`, `spt`, `firecracker`, `cloud-hypervisor`) are NOT valid base64, so they correctly return errors.

### Reproduction

```bash
go test -run='^FuzzConfigDecode$' -fuzz='^FuzzConfigDecode$' -fuzztime=10s ./pkg/unikontainers/
```

Output:
```
--- FAIL: FuzzConfigDecode (0.00s)
    config_fuzz_test.go:86: decode() round-trip violation: input="\r",
        decoded="", re-encoded="" (expected re-encoded == input)
```

### Root Cause

The config pipeline has two entry points:

1. **Via containerd shim:** Annotations are base64-encoded by bima (image builder) → stored in OCI manifest → fetched by shim (`annotations.go`) → patched into `config.json` → read by `getConfigFromSpec()`. In this path, `decode()` on line 109 of `config.go` correctly decodes the base64 values.

2. **Without shim (direct invocation):** Annotations arrive as plaintext (e.g., `ctr run --annotation com.urunc.unikernel.hypervisor=qemu`). The `TODO` comment on line 86 acknowledges this: *"in case of urunc executed without shim, the annotations would remain encoded"*. But `decode()` runs unconditionally and corrupts the already-plaintext values.

The function has no way to distinguish between:
- `"cWVtdQ=="` — the string "qemu" properly base64-encoded (SHOULD decode)
- `"qemu"` — the literal string "qemu" (should NOT decode)

Both are valid base64. The ambiguity is protocol-level.

### Impact

When urunc runs without the containerd shim, annotations arrive as plaintext. `decode()` silently converts `hypervisor: "qemu"` to `hypervisor: "\xa9\xe9\xae"`. The VMM lookup then fails with "vmm not found" — with no indication the config was mangled.

### Proposed Fix Direction

**Try-decode-then-validate with UTF-8 heuristic:**
```go
func (c *UnikernelConfig) decode() error {
    for _, field := range c.allFields() {
        decoded, err := base64.StdEncoding.DecodeString(*field)
        if err != nil {
            continue // Not valid base64 — keep original
        }
        if utf8.Valid(decoded) {
            *field = string(decoded)
        }
        // If decoded bytes aren't valid UTF-8, the original was
        // coincidentally valid base64 — keep the original value
    }
    return nil
}
```

This works for `"qemu"` → `"\xa9\xe9\xae"` (not valid UTF-8, kept as-is), but needs maintainer input for edge cases where decoded bytes happen to be valid UTF-8.

---

## Bug 2: `subnetMaskToCIDR()` Accepts Non-Contiguous Masks

**File:** `pkg/unikontainers/unikernels/utils.go:24`  
**Severity:** Medium — causes silent network misconfiguration  
**Related:** [#909](https://github.com/urunc-dev/urunc/issues/909)

### Description

`subnetMaskToCIDR()` converts a dotted-decimal subnet mask to a CIDR prefix length by counting all `1` bits. It does **not** check that the bits are contiguous from the left, which is a requirement for a valid subnet mask.

### Affected Values

| Input | Returned | Correct Answer | Binary |
|---|---|---|---|
| `"255.0.255.0"` | `16` | **Error** | `11111111.00000000.11111111.00000000` |
| `"128.0.128.0"` | `2` | **Error** | `10000000.00000000.10000000.00000000` |
| `"255.128.255.0"` | `17` | **Error** | `11111111.10000000.11111111.00000000` |

### Reproduction

```bash
go test -run='^FuzzSubnetMaskToCIDR$' -fuzz='^FuzzSubnetMaskToCIDR$' -fuzztime=10s ./pkg/unikontainers/unikernels/
```

Output:
```
--- FAIL: FuzzSubnetMaskToCIDR (0.00s)
    utils_fuzz_test.go:80: subnetMaskToCIDR("255.0.255.0") = 16
        but Go's net.IPMask considers it non-contiguous (invalid mask)
```

### Verification

Go's standard library confirms these are invalid:
```go
mask := net.IPMask(net.ParseIP("255.0.255.0").To4())
ones, bits := mask.Size()
// ones=0, bits=0 — Size() returns (0,0) for non-contiguous masks
```

### Root Cause

The function counts `1` bits per octet independently:
```go
for _, part := range parts {
    cidr += bits.OnesCount(uint(part))
}
```

It never checks whether the overall 32-bit pattern forms a valid contiguous prefix.

### Impact

A non-contiguous mask like `"255.0.255.0"` produces `/16`, which would misconfigure the unikernel's network interface. Traffic would be routed incorrectly, potentially breaking connectivity or creating a security boundary violation.

### Proposed Fix

After counting bits, verify contiguity:
```go
maskVal := uint32(parts[0])<<24 | uint32(parts[1])<<16 | uint32(parts[2])<<8 | uint32(parts[3])
inverted := ^maskVal & 0xFFFFFFFF
if maskVal != 0 && maskVal != 0xFFFFFFFF && (inverted&(inverted+1)) != 0 {
    return 0, fmt.Errorf("non-contiguous subnet mask: %s", subnetMask)
}
```

The check works because a valid mask's inverted form (e.g., `0x00FFFFFF` for `/8`) is always of the form `0...01...1`, meaning `(inverted & (inverted + 1)) == 0`.
