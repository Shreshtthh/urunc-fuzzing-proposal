// Copyright (c) 2023-2026, Nubificus LTD
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package unikontainers

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/opencontainers/runtime-spec/specs-go"
)

// FuzzConfigDecode tests the decode() method for silent data corruption.
//
// Property under test: for any input string, decode() must either:
//   - Return an error (rejecting the input), OR
//   - Produce a decoded value that, when re-encoded, equals the original input.
//
// This catches the known bug where plaintext values like "qemu", "unikraft",
// and "mewz" happen to be valid base64 and get silently corrupted to garbage
// bytes (e.g. "qemu" → "\xa9\xe9\xae") without returning an error.
func FuzzConfigDecode(f *testing.F) {
	// Seed corpus: known hypervisor/unikernel names that are used in practice.
	// Some of these ("qemu", "unikraft", "mewz") trigger silent corruption.
	seeds := []string{
		"qemu", "hvt", "spt", "firecracker", "cloud-hypervisor",
		"unikraft", "rumprun", "mirage", "mewz", "hermit",
		// Properly base64-encoded values (should decode cleanly)
		base64.StdEncoding.EncodeToString([]byte("qemu")),
		base64.StdEncoding.EncodeToString([]byte("firecracker")),
		base64.StdEncoding.EncodeToString([]byte("/usr/bin/kernel")),
		base64.StdEncoding.EncodeToString([]byte("")),
		// Edge cases
		"",           // empty string
		"====",       // padding only
		"YQ==",       // single character "a"
		"not-base64!", // clearly invalid
		"\x00\x01\x02", // binary data
	}

	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, input string) {
		// Test each field individually since decode() processes them sequentially
		// and stops at the first error. We use Hypervisor as the test field.
		c := UnikernelConfig{
			// Set all other fields to valid base64 so decode() reaches Hypervisor
			UnikernelCmd:     base64.StdEncoding.EncodeToString([]byte("cmd")),
			Hypervisor:       input,
			UnikernelType:    base64.StdEncoding.EncodeToString([]byte("type")),
			UnikernelVersion: base64.StdEncoding.EncodeToString([]byte("ver")),
			UnikernelBinary:  base64.StdEncoding.EncodeToString([]byte("bin")),
			Initrd:           base64.StdEncoding.EncodeToString([]byte("")),
			Block:            base64.StdEncoding.EncodeToString([]byte("")),
			BlkMntPoint:      base64.StdEncoding.EncodeToString([]byte("")),
			MountRootfs:      base64.StdEncoding.EncodeToString([]byte("true")),
			NetDev:           base64.StdEncoding.EncodeToString([]byte("")),
			BlkDev:           base64.StdEncoding.EncodeToString([]byte("")),
		}

		err := c.decode()

		if err != nil {
			// Rejecting the input with an error is always acceptable.
			return
		}

		// If decode() succeeded without error, verify the round-trip property:
		// re-encoding the decoded Hypervisor value should produce the original input.
		reEncoded := base64.StdEncoding.EncodeToString([]byte(c.Hypervisor))
		if reEncoded != input {
			t.Errorf(
				"decode() round-trip violation: input=%q, decoded=%q, re-encoded=%q (expected re-encoded == input)",
				input, c.Hypervisor, reEncoded,
			)
		}
	})
}

// FuzzConfigDecodeAllFields tests that decode() handles all 11 fields
// consistently — either all succeed or it returns an error at the first failure.
func FuzzConfigDecodeAllFields(f *testing.F) {
	f.Add(
		base64.StdEncoding.EncodeToString([]byte("cmd")),
		base64.StdEncoding.EncodeToString([]byte("qemu")),
		base64.StdEncoding.EncodeToString([]byte("unikraft")),
	)
	f.Add("qemu", "qemu", "qemu") // all plaintext — triggers silent corruption
	f.Add("", "", "")             // all empty
	f.Add("!!!", "!!!", "!!!")     // all invalid base64

	f.Fuzz(func(t *testing.T, cmd, hypervisor, unikernelType string) {
		c := UnikernelConfig{
			UnikernelCmd:     cmd,
			Hypervisor:       hypervisor,
			UnikernelType:    unikernelType,
			UnikernelVersion: base64.StdEncoding.EncodeToString([]byte("")),
			UnikernelBinary:  base64.StdEncoding.EncodeToString([]byte("")),
			Initrd:           base64.StdEncoding.EncodeToString([]byte("")),
			Block:            base64.StdEncoding.EncodeToString([]byte("")),
			BlkMntPoint:      base64.StdEncoding.EncodeToString([]byte("")),
			MountRootfs:      base64.StdEncoding.EncodeToString([]byte("")),
			NetDev:           base64.StdEncoding.EncodeToString([]byte("")),
			BlkDev:           base64.StdEncoding.EncodeToString([]byte("")),
		}

		err := c.decode()
		if err != nil {
			return
		}

		// Verify no field was silently corrupted
		for _, tc := range []struct {
			name     string
			original string
			decoded  string
		}{
			{"UnikernelCmd", cmd, c.UnikernelCmd},
			{"Hypervisor", hypervisor, c.Hypervisor},
			{"UnikernelType", unikernelType, c.UnikernelType},
		} {
			reEncoded := base64.StdEncoding.EncodeToString([]byte(tc.decoded))
			if reEncoded != tc.original {
				t.Errorf(
					"field %s silently corrupted: input=%q, decoded=%q, re-encoded=%q",
					tc.name, tc.original, tc.decoded, reEncoded,
				)
			}
		}
	})
}

// FuzzConfigValidate tests that validate() never panics on arbitrary field combinations.
func FuzzConfigValidate(f *testing.F) {
	f.Add("unikraft", "qemu", "/kernel")
	f.Add("", "", "")
	f.Add("type", "", "/bin")
	f.Add("", "hvt", "")

	f.Fuzz(func(t *testing.T, unikernelType, hypervisor, binary string) {
		c := UnikernelConfig{
			UnikernelType:   unikernelType,
			Hypervisor:      hypervisor,
			UnikernelBinary: binary,
		}

		err := c.validate()

		// validate() should return error iff any mandatory field is empty
		allPresent := unikernelType != "" && hypervisor != "" && binary != ""
		if allPresent && err != nil {
			t.Errorf("validate() returned error with all mandatory fields present: %v", err)
		}
		if !allPresent && err == nil {
			t.Errorf("validate() returned nil with missing mandatory fields: type=%q hypervisor=%q binary=%q",
				unikernelType, hypervisor, binary)
		}
	})
}

// FuzzConfigJSONRoundTrip tests that UnikernelConfig survives JSON marshal/unmarshal
// without losing data or panicking.
func FuzzConfigJSONRoundTrip(f *testing.F) {
	f.Add([]byte(`{
		"com.urunc.unikernel.unikernelType": "unikraft",
		"com.urunc.unikernel.binary": "/unikernel/kernel",
		"com.urunc.unikernel.hypervisor": "qemu",
		"com.urunc.unikernel.mountRootfs": "true"
	}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`{"com.urunc.unikernel.hypervisor": ""}`))
	f.Add([]byte(`[]`))          // wrong type
	f.Add([]byte(`{`))           // truncated
	f.Add([]byte(``))            // empty
	f.Add([]byte(`{"extra_field": "value"}`)) // unknown fields

	f.Fuzz(func(t *testing.T, data []byte) {
		var config UnikernelConfig
		err := json.Unmarshal(data, &config)
		if err != nil {
			// Invalid JSON is fine to reject
			return
		}

		// If unmarshal succeeded, validate() must not panic
		_ = config.validate()

		// Re-marshal must not panic and must succeed
		remarshalled, err := json.Marshal(config)
		if err != nil {
			t.Fatalf("config that unmarshalled successfully could not re-marshal: %v", err)
		}

		// Unmarshal the re-marshalled data and compare
		var config2 UnikernelConfig
		err = json.Unmarshal(remarshalled, &config2)
		if err != nil {
			t.Fatalf("re-marshalled JSON could not be unmarshalled: %v", err)
		}

		if config != config2 {
			t.Errorf("JSON round-trip changed config:\n  before: %+v\n  after:  %+v", config, config2)
		}
	})
}

// FuzzGetConfigFromSpec tests that getConfigFromSpec never panics when given
// arbitrary annotation key-value pairs.
func FuzzGetConfigFromSpec(f *testing.F) {
	f.Add("unikraft", "qemu", "/kernel", "true")
	f.Add("", "", "", "")
	f.Add("a]b[c", "d{e}f", "g\x00h", "\n\t")

	f.Fuzz(func(t *testing.T, unikernelType, hypervisor, binary, mountRootfs string) {
		spec := &specs.Spec{
			Annotations: map[string]string{
				annotType:        unikernelType,
				annotHypervisor:  hypervisor,
				annotBinary:      binary,
				annotMountRootfs: mountRootfs,
			},
		}

		config := getConfigFromSpec(spec)
		if config == nil {
			t.Fatal("getConfigFromSpec returned nil")
		}

		// Verify the values were copied correctly
		if config.UnikernelType != unikernelType {
			t.Errorf("UnikernelType mismatch: got %q, want %q", config.UnikernelType, unikernelType)
		}
		if config.Hypervisor != hypervisor {
			t.Errorf("Hypervisor mismatch: got %q, want %q", config.Hypervisor, hypervisor)
		}
		if config.UnikernelBinary != binary {
			t.Errorf("UnikernelBinary mismatch: got %q, want %q", config.UnikernelBinary, binary)
		}

		// Map() must not panic and must produce valid output
		m := config.Map()
		if m == nil {
			t.Fatal("Map() returned nil")
		}
	})
}
