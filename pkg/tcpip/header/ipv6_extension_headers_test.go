// Copyright 2020 The gVisor Authors.
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

package header

import (
	"errors"
	"io"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestIPv6RoutingExtHdr(t *testing.T) {
	tests := []struct {
		name         string
		bytes        []byte
		segmentsLeft uint8
	}{
		{
			name:         "Zeroes",
			bytes:        []byte{0, 0, 0, 0, 0, 0},
			segmentsLeft: 0,
		},
		{
			name:         "Ones",
			bytes:        []byte{1, 1, 1, 1, 1, 1},
			segmentsLeft: 1,
		},
		{
			name:         "Mixed",
			bytes:        []byte{1, 2, 3, 4, 5, 6},
			segmentsLeft: 2,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			extHdr := IPv6RoutingExtHdr(test.bytes)
			if got := extHdr.SegmentsLeft(); got != test.segmentsLeft {
				t.Errorf("got SegmentsLeft() = %d, want = %d", got, test.segmentsLeft)
			}
		})
	}
}

func TestIPv6FragmentExtHdr(t *testing.T) {
	tests := []struct {
		name           string
		bytes          []byte
		fragmentOffset uint16
		more           bool
		id             uint32
	}{
		{
			name:           "Zeroes",
			bytes:          []byte{0, 0, 0, 0, 0, 0},
			fragmentOffset: 0,
			more:           false,
			id:             0,
		},
		{
			name:           "Ones",
			bytes:          []byte{0, 9, 0, 0, 0, 1},
			fragmentOffset: 1,
			more:           true,
			id:             1,
		},
		{
			name:           "Mixed",
			bytes:          []byte{68, 9, 128, 4, 2, 1},
			fragmentOffset: 2177,
			more:           true,
			id:             2147746305,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			extHdr := IPv6FragmentExtHdr(test.bytes)
			if got := extHdr.FragmentOffset(); got != test.fragmentOffset {
				t.Errorf("got FragmentOffset() = %d, want = %d", got, test.fragmentOffset)
			}
			if got := extHdr.More(); got != test.more {
				t.Errorf("got More() = %t, want = %t", got, test.more)
			}
			if got := extHdr.ID(); got != test.id {
				t.Errorf("got ID() = %d, want = %d", got, test.id)
			}
		})
	}
}

func TestIPv6ExtHdrIterErr(t *testing.T) {
	tests := []struct {
		name         string
		firstNextHdr uint8
		payload      []byte
		err          error
	}{
		{
			name:         "Upper layer only without data",
			firstNextHdr: 255,
		},
		{
			name:         "Upper layer only with data",
			firstNextHdr: 255,
			payload:      []byte{1, 2, 3, 4},
		},

		{
			name:         "No next header",
			firstNextHdr: ipv6NoNextHeaderIdentifier,
		},
		{
			name:         "No next header with data",
			firstNextHdr: ipv6NoNextHeaderIdentifier,
			payload:      []byte{1, 2, 3, 4},
		},

		{
			name:         "Valid single fragment",
			firstNextHdr: ipv6FragmentExtHdrIdentifier,
			payload:      []byte{255, 0, 68, 9, 128, 4, 2, 1},
		},
		{
			name:         "Fragment too small",
			firstNextHdr: ipv6FragmentExtHdrIdentifier,
			payload:      []byte{255, 0, 68, 9, 128, 4, 2},
			err:          io.EOF,
		},

		{
			name:         "Valid single routing",
			firstNextHdr: ipv6RoutingExtHdrIdentifier,
			payload:      []byte{255, 0, 1, 2, 3, 4, 5, 6},
		},
		{
			name:         "Routing too small with zero length field",
			firstNextHdr: ipv6RoutingExtHdrIdentifier,
			payload:      []byte{255, 0, 1, 2, 3, 4, 5},
			err:          io.EOF,
		},
		{
			name:         "Valid Routing with non-zero length field",
			firstNextHdr: ipv6RoutingExtHdrIdentifier,
			payload:      []byte{255, 1, 1, 2, 3, 4, 5, 6, 1, 2, 3, 4, 5, 6, 7, 8},
		},
		{
			name:         "Routing too small with non-zero length field",
			firstNextHdr: ipv6RoutingExtHdrIdentifier,
			payload:      []byte{255, 1, 1, 2, 3, 4, 5, 6, 1, 2, 3, 4, 5, 6, 7},
			err:          io.EOF,
		},

		{
			name:         "Mixed",
			firstNextHdr: ipv6FragmentExtHdrIdentifier,
			payload: []byte{
				// Fragment extension header.
				ipv6RoutingExtHdrIdentifier, 0, 68, 9, 128, 4, 2, 1,

				// Routing extension header.
				255, 0, 1, 2, 3, 4, 5, 6,

				// Upper layer data.
				1, 2, 3, 4,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := MakeIPv6PayloadIterator(test.firstNextHdr, test.payload, false); err != nil {
				t.Errorf("got MakeIPv6PayloadIterator(%d, _, false) = %s, want = nil", test.firstNextHdr, err)
			}

			if _, err := MakeIPv6PayloadIterator(test.firstNextHdr, test.payload, true); !errors.Is(err, test.err) {
				t.Errorf("got MakeIPv6PayloadIterator(%d, _, true) = %v, want = %v", test.firstNextHdr, err, test.err)
			}
		})
	}
}

func TestIPv6ExtHdrIter(t *testing.T) {
	tests := []struct {
		name         string
		firstNextHdr uint8
		payload      []byte
		expected     []IPv6PayloadHeader
	}{
		// With a non-atomic fragment, the payload after the fragment will not be
		// parsed because the payload may not be complete.
		{
			name:         "fragment - routing - upper",
			firstNextHdr: ipv6FragmentExtHdrIdentifier,
			payload: []byte{
				// Fragment extension header.
				ipv6RoutingExtHdrIdentifier, 0, 68, 9, 128, 4, 2, 1,

				// Routing extension header.
				255, 0, 1, 2, 3, 4, 5, 6,

				// Upper layer data.
				1, 2, 3, 4,
			},
			expected: []IPv6PayloadHeader{
				IPv6FragmentExtHdr([]byte{68, 9, 128, 4, 2, 1}),
				IPv6RawPayloadHeader{Identifier: ipv6RoutingExtHdrIdentifier, Buf: []byte{255, 0, 1, 2, 3, 4, 5, 6, 1, 2, 3, 4}},
			},
		},

		// If we have an atomic fragment, the payload following the fragment
		// extension header should be parsed normally.
		{
			name:         "atomic fragment - routing - upper",
			firstNextHdr: ipv6FragmentExtHdrIdentifier,
			payload: []byte{
				// Fragment extension header.
				//
				// Res (Reserved) bits are 1 which should not affect anything.
				ipv6RoutingExtHdrIdentifier, 0, 0, 6, 128, 4, 2, 1,

				// Routing extension header.
				255, 0, 1, 2, 3, 4, 5, 6,

				// Upper layer data.
				1, 2, 3, 4,
			},
			expected: []IPv6PayloadHeader{
				IPv6FragmentExtHdr([]byte{0, 6, 128, 4, 2, 1}),
				IPv6RoutingExtHdr([]byte{1, 2, 3, 4, 5, 6}),
				IPv6RawPayloadHeader{Identifier: 255, Buf: []byte{1, 2, 3, 4}},
			},
		},
		{
			name:         "atomic fragment - no next header",
			firstNextHdr: ipv6FragmentExtHdrIdentifier,
			payload: []byte{
				// Fragment extension header.
				//
				// Res (Reserved) bits are 1 which should not affect anything.
				ipv6NoNextHeaderIdentifier, 0, 0, 6, 128, 4, 2, 1,

				// Random data.
				1, 2, 3, 4,
			},
			expected: []IPv6PayloadHeader{
				IPv6FragmentExtHdr([]byte{0, 6, 128, 4, 2, 1}),
			},
		},
		{
			name:         "routing - atomic fragment - no next header",
			firstNextHdr: ipv6RoutingExtHdrIdentifier,
			payload: []byte{
				// Routing extension header.
				ipv6FragmentExtHdrIdentifier, 0, 1, 2, 3, 4, 5, 6,

				// Fragment extension header.
				//
				// Res (Reserved) bits are 1 which should not affect anything.
				ipv6NoNextHeaderIdentifier, 0, 0, 6, 128, 4, 2, 1,

				// Random data.
				1, 2, 3, 4,
			},
			expected: []IPv6PayloadHeader{
				IPv6RoutingExtHdr([]byte{1, 2, 3, 4, 5, 6}),
				IPv6FragmentExtHdr([]byte{0, 6, 128, 4, 2, 1}),
			},
		},
		{
			name:         "routing - fragment - no next header",
			firstNextHdr: ipv6RoutingExtHdrIdentifier,
			payload: []byte{
				// Routing extension header.
				ipv6FragmentExtHdrIdentifier, 0, 1, 2, 3, 4, 5, 6,

				// Fragment extension header.
				//
				// Fragment Offset = 32; Res = 6.
				ipv6NoNextHeaderIdentifier, 0, 1, 6, 128, 4, 2, 1,

				// Random data.
				1, 2, 3, 4,
			},
			expected: []IPv6PayloadHeader{
				IPv6RoutingExtHdr([]byte{1, 2, 3, 4, 5, 6}),
				IPv6FragmentExtHdr([]byte{1, 6, 128, 4, 2, 1}),
				IPv6RawPayloadHeader{Identifier: ipv6NoNextHeaderIdentifier, Buf: []byte{1, 2, 3, 4}},
			},
		},

		// Test the raw payload for common transport layer protocol numbers.
		{
			name:         "TCP raw payload",
			firstNextHdr: uint8(TCPProtocolNumber),
			payload:      []byte{1, 2, 3, 4},
			expected:     []IPv6PayloadHeader{IPv6RawPayloadHeader{Identifier: uint8(TCPProtocolNumber), Buf: []byte{1, 2, 3, 4}}},
		},
		{
			name:         "UDP raw payload",
			firstNextHdr: uint8(UDPProtocolNumber),
			payload:      []byte{1, 2, 3, 4},
			expected:     []IPv6PayloadHeader{IPv6RawPayloadHeader{Identifier: uint8(UDPProtocolNumber), Buf: []byte{1, 2, 3, 4}}},
		},
		{
			name:         "ICMPv4 raw payload",
			firstNextHdr: uint8(ICMPv4ProtocolNumber),
			payload:      []byte{1, 2, 3, 4},
			expected:     []IPv6PayloadHeader{IPv6RawPayloadHeader{Identifier: uint8(ICMPv4ProtocolNumber), Buf: []byte{1, 2, 3, 4}}},
		},
		{
			name:         "ICMPv6 raw payload",
			firstNextHdr: uint8(ICMPv6ProtocolNumber),
			payload:      []byte{1, 2, 3, 4},
			expected:     []IPv6PayloadHeader{IPv6RawPayloadHeader{Identifier: uint8(ICMPv6ProtocolNumber), Buf: []byte{1, 2, 3, 4}}},
		},
		{
			name:         "Unknwon next header raw payload",
			firstNextHdr: 255,
			payload:      []byte{1, 2, 3, 4},
			expected:     []IPv6PayloadHeader{IPv6RawPayloadHeader{Identifier: 255, Buf: []byte{1, 2, 3, 4}}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			it, err := MakeIPv6PayloadIterator(test.firstNextHdr, test.payload, true)
			if err != nil {
				t.Fatalf("MakeIPv6PayloadIterator(%d, _ true): %s", test.firstNextHdr, err)
			}

			for i, e := range test.expected {
				extHdr, done, err := it.Next()
				if err != nil {
					t.Errorf("(i=%d) Next(): %s", i, err)
				}
				if done {
					t.Errorf("(i=%d) unexpectedly done iterating", i)
				}
				if diff := cmp.Diff(e, extHdr); diff != "" {
					t.Errorf("(i=%d) got ext hdr mismatch (-want +got):\n%s", i, diff)
				}

				if t.Failed() {
					t.FailNow()
				}
			}

			extHdr, done, err := it.Next()
			if err != nil {
				t.Errorf("(last) Next(): %s", err)
			}
			if !done {
				t.Errorf("(last) iterator unexpectedly not done")
			}
			if extHdr != nil {
				t.Errorf("(last) got Next() = %T, want = nil", extHdr)
			}
		})
	}
}
