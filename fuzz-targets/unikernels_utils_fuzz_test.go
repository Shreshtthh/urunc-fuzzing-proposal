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

package unikernels

import (
	"fmt"
	"net"
	"testing"
)

// FuzzSubnetMaskToCIDR tests subnetMaskToCIDR for:
// 1. No panics on arbitrary input
// 2. Output is in valid CIDR range [0, 32] on success
// 3. Non-contiguous masks are rejected (known bug #909)
//
// The known bug: subnetMaskToCIDR("255.0.255.0") returns 16 (counting all 1-bits)
// instead of rejecting it. A valid subnet mask must have all 1-bits contiguous
// from the left (e.g. 255.255.0.0 is valid, 255.0.255.0 is NOT).
func FuzzSubnetMaskToCIDR(f *testing.F) {
	// Valid subnet masks
	f.Add("255.255.255.0")   // /24
	f.Add("255.255.0.0")     // /16
	f.Add("255.0.0.0")       // /8
	f.Add("255.255.255.255") // /32
	f.Add("0.0.0.0")         // /0

	// Non-contiguous masks — should be rejected but currently aren't (#909)
	f.Add("255.0.255.0")   // non-contiguous
	f.Add("128.0.128.0")   // non-contiguous
	f.Add("255.128.255.0") // non-contiguous

	// Invalid formats
	f.Add("")                    // empty
	f.Add("255")                 // single octet
	f.Add("255.255")             // two octets
	f.Add("255.255.255")         // three octets
	f.Add("255.255.255.255.255") // five octets
	f.Add("256.0.0.0")           // out of range
	f.Add("-1.0.0.0")            // negative
	f.Add("abc.def.ghi.jkl")     // non-numeric
	f.Add("255.255.255.0\n")     // trailing newline
	f.Add("255.255.255.0 ")      // trailing space

	f.Fuzz(func(t *testing.T, input string) {
		cidr, err := subnetMaskToCIDR(input)
		if err != nil {
			// Rejecting invalid input is always correct
			return
		}

		// CIDR must be in valid range
		if cidr < 0 || cidr > 32 {
			t.Errorf("subnetMaskToCIDR(%q) = %d, which is outside valid range [0, 32]",
				input, cidr)
		}

		// Cross-validate with Go's net package: parse the mask and compare
		// the CIDR prefix length. This also implicitly checks contiguity
		// since net.IPMask.Size() returns (0,0) for non-contiguous masks.
		ip := net.ParseIP(input)
		if ip != nil {
			ipv4 := ip.To4()
			if ipv4 != nil {
				mask := net.IPMask(ipv4)
				ones, bits := mask.Size()
				if bits == 0 {
					// net.IPMask.Size() returns (0,0) for non-contiguous masks
					t.Errorf(
						"subnetMaskToCIDR(%q) = %d but Go's net.IPMask considers it non-contiguous (invalid mask)",
						input, cidr,
					)
				} else if ones != cidr {
					t.Errorf(
						"subnetMaskToCIDR(%q) = %d but Go's net.IPMask says %d",
						input, cidr, ones,
					)
				}
			}
		}
	})
}

// FuzzSubnetMaskToCIDRContiguity specifically tests that non-contiguous masks
// are properly rejected. This is a targeted regression test for issue #909.
func FuzzSubnetMaskToCIDRContiguity(f *testing.F) {
	// Seed with some known non-contiguous masks
	f.Add(uint8(255), uint8(0), uint8(255), uint8(0))   // 255.0.255.0
	f.Add(uint8(128), uint8(0), uint8(128), uint8(0))   // 128.0.128.0
	f.Add(uint8(255), uint8(128), uint8(255), uint8(0)) // 255.128.255.0
	// And some valid contiguous masks
	f.Add(uint8(255), uint8(255), uint8(255), uint8(0)) // 255.255.255.0
	f.Add(uint8(255), uint8(255), uint8(0), uint8(0))   // 255.255.0.0
	f.Add(uint8(255), uint8(0), uint8(0), uint8(0))     // 255.0.0.0
	f.Add(uint8(0), uint8(0), uint8(0), uint8(0))       // 0.0.0.0

	f.Fuzz(func(t *testing.T, a, b, c, d uint8) {
		input := fmt.Sprintf("%d.%d.%d.%d", a, b, c, d)
		cidr, err := subnetMaskToCIDR(input)
		if err != nil {
			return
		}

		// Check contiguity: a valid mask in binary must be a run of 1s
		// followed by a run of 0s (e.g. 11111111.11111111.00000000.00000000).
		//
		// For the inverted mask (all 0s then all 1s), the property is:
		// (inverted & (inverted + 1)) == 0, meaning inverted is of the
		// form 0...01...1 (a power-of-two minus one).
		maskVal := uint32(a)<<24 | uint32(b)<<16 | uint32(c)<<8 | uint32(d)
		inverted := ^maskVal & 0xFFFFFFFF

		// Special cases: all-ones and all-zeros are always contiguous
		if maskVal == 0 || maskVal == 0xFFFFFFFF {
			return
		}

		if (inverted & (inverted + 1)) != 0 {
			t.Errorf(
				"subnetMaskToCIDR(%q) = %d but the mask is non-contiguous (binary: %032b)",
				input, cidr, maskVal,
			)
		}
	})
}
