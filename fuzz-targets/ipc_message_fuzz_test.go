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
	"testing"
)

// FuzzBytemsgSerialize tests that bytemsg.Serialize() never panics
// for payloads under the size limit and that the output length
// is properly NLA-aligned.
func FuzzBytemsgSerialize(f *testing.F) {
	f.Add(uint16(0), []byte(""))
	f.Add(uint16(27281), []byte("hello"))
	f.Add(uint16(62000), []byte{0x00, 0x01, 0x02, 0x03})
	f.Add(uint16(65535), []byte("a]b[c{d}e"))

	f.Fuzz(func(t *testing.T, msgType uint16, value []byte) {
		msg := &bytemsg{
			Type:  msgType,
			Value: value,
		}

		msgLen := msg.Len()

		// If the message is too large, Serialize() is expected to panic
		// with a netlinkError. We verify the panic is the right type.
		if msgLen > 0xFFFF {
			defer func() {
				r := recover()
				if r == nil {
					t.Fatal("expected panic for oversized bytemsg, but did not panic")
				}
				if _, ok := r.(netlinkError); !ok {
					t.Fatalf("expected netlinkError panic, got: %T: %v", r, r)
				}
			}()
			_ = msg.Serialize()
			return
		}

		buf := msg.Serialize()

		// Output must not be nil
		if buf == nil {
			t.Fatal("Serialize() returned nil for a valid message")
		}

		// Length must be NLA-aligned (multiple of 4)
		if len(buf)%4 != 0 {
			t.Errorf("Serialize() output length %d is not NLA-aligned (must be multiple of 4)",
				len(buf))
		}

		// Output length must be >= the declared Len()
		if len(buf) < msgLen {
			t.Errorf("Serialize() output length %d < Len() %d", len(buf), msgLen)
		}
	})
}

// FuzzInt32msgSerialize tests that int32msg.Serialize() produces
// correctly sized output for any type and value combination.
func FuzzInt32msgSerialize(f *testing.F) {
	f.Add(uint16(0), uint32(0))
	f.Add(uint16(27281), uint32(1))
	f.Add(uint16(62000), uint32(0xFFFFFFFF))
	f.Add(uint16(65535), uint32(256))

	f.Fuzz(func(t *testing.T, msgType uint16, value uint32) {
		msg := &int32msg{
			Type:  msgType,
			Value: value,
		}

		buf := msg.Serialize()

		expectedLen := msg.Len()
		if len(buf) != expectedLen {
			t.Errorf("int32msg.Serialize() length = %d, want %d", len(buf), expectedLen)
		}

		// Verify the output is exactly 8 bytes (4 header + 4 value)
		if len(buf) != 8 {
			t.Errorf("int32msg.Serialize() should always be 8 bytes, got %d", len(buf))
		}
	})
}
