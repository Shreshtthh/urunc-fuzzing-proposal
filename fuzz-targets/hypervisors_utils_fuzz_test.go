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

package hypervisors

import (
	"math"
	"strconv"
	"testing"
)

// FuzzBytesToMiB tests that bytesToMiB never panics and always satisfies
// the invariant: result * 1024 * 1024 <= input.
func FuzzBytesToMiB(f *testing.F) {
	f.Add(uint64(0))
	f.Add(uint64(1))
	f.Add(uint64(1024*1024 - 1))
	f.Add(uint64(1024 * 1024))
	f.Add(uint64(1024*1024 + 1))
	f.Add(uint64(256 * 1024 * 1024))
	f.Add(uint64(math.MaxUint64))

	f.Fuzz(func(t *testing.T, input uint64) {
		result := bytesToMiB(input)

		// Invariant: result must not exceed the actual number of MiB
		const mib = uint64(1024 * 1024)
		expected := input / mib
		if result != expected {
			t.Errorf("bytesToMiB(%d) = %d, want %d", input, result, expected)
		}

		// Result converted back should not exceed input
		if result > 0 && result <= math.MaxUint64/mib {
			backToBytes := result * mib
			if backToBytes > input {
				t.Errorf("bytesToMiB(%d) = %d, but %d * MiB = %d > input",
					input, result, result, backToBytes)
			}
		}
	})
}

// FuzzBytesToMB tests that bytesToMB never panics and preserves the invariant.
func FuzzBytesToMB(f *testing.F) {
	f.Add(uint64(0))
	f.Add(uint64(1))
	f.Add(uint64(999999))
	f.Add(uint64(1000000))
	f.Add(uint64(1000001))
	f.Add(uint64(256 * 1000 * 1000))
	f.Add(uint64(math.MaxUint64))

	f.Fuzz(func(t *testing.T, input uint64) {
		result := bytesToMB(input)

		const mb = uint64(1000 * 1000)
		expected := input / mb
		if result != expected {
			t.Errorf("bytesToMB(%d) = %d, want %d", input, result, expected)
		}
	})
}

// FuzzBytesToStringMB tests BytesToStringMB for:
// 1. No panics on any input
// 2. Output is always a valid numeric string
// 3. Output is never "0" for non-zero inputs (would crash a VM)
func FuzzBytesToStringMB(f *testing.F) {
	f.Add(uint64(0))
	f.Add(uint64(1))
	f.Add(uint64(999999))    // less than 1 MB — should fall back to DefaultMemory
	f.Add(uint64(1000000))   // exactly 1 MB
	f.Add(uint64(256000000)) // 256 MB
	f.Add(uint64(math.MaxUint64))

	f.Fuzz(func(t *testing.T, input uint64) {
		result := BytesToStringMB(input)

		// Output must always be a valid unsigned integer string
		val, err := strconv.ParseUint(result, 10, 64)
		if err != nil {
			t.Fatalf("BytesToStringMB(%d) = %q, which is not a valid uint64: %v",
				input, result, err)
		}

		// Output must never be "0" — a 0 MB VM would fail to boot
		if val == 0 {
			t.Errorf("BytesToStringMB(%d) = \"0\": zero MB memory would crash a VM", input)
		}

		// For zero input, should return DefaultMemory
		if input == 0 {
			expectedDefault := strconv.FormatUint(DefaultMemory, 10)
			if result != expectedDefault {
				t.Errorf("BytesToStringMB(0) = %q, want default %q", result, expectedDefault)
			}
		}
	})
}

// FuzzAppendNonEmpty tests that appendNonEmpty never panics and satisfies
// basic string invariants.
func FuzzAppendNonEmpty(f *testing.F) {
	f.Add("body", "--prefix=", "value")
	f.Add("", "", "")
	f.Add("body", "--prefix=", "")
	f.Add("", "--mem=", "256")

	f.Fuzz(func(t *testing.T, body, prefix, value string) {
		result := appendNonEmpty(body, prefix, value)

		if value == "" {
			// When value is empty, result must equal body unchanged
			if result != body {
				t.Errorf("appendNonEmpty(%q, %q, %q) = %q, want %q (value is empty)",
					body, prefix, value, result, body)
			}
		} else {
			// When value is non-empty, result must equal body + prefix + value
			expected := body + prefix + value
			if result != expected {
				t.Errorf("appendNonEmpty(%q, %q, %q) = %q, want %q",
					body, prefix, value, result, expected)
			}
		}
	})
}
