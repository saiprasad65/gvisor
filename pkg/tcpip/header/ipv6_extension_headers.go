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
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

const (
	// ipv6HopByHopOptsExtHdrIdentifier is the identifier of a Hop by Hop Options
	// extension header, as per RFC 8200 section 4.3.
	ipv6HopByHopOptsExtHdrIdentifier = 0

	// ipv6RoutingExtHdrIdentifier is the identifier of a Routing extension
	// header, as per RFC 8200 section 4.4.
	ipv6RoutingExtHdrIdentifier = 43

	// ipv6RoutingExtHdrSegmentsLeftIdx is the index to the Segments Left field
	// within an IPv6RoutingExtHdr.
	ipv6RoutingExtHdrSegmentsLeftIdx = 1

	// ipv6FragmentExtHdrIdentifier is the identifier of a Fragment extension
	// header, as per RFC 8200 section 4.5.
	ipv6FragmentExtHdrIdentifier = 44

	// ipv6FragmentExtHdrFragmentOffsetOffset is the offset to the start of the
	// Fragment Offset field within an IPv6FragmentExtHdr.
	ipv6FragmentExtHdrFragmentOffsetOffset = 0

	// ipv6FragmentExtHdrFragmentOffsetOffset is the number of least significant
	// bits to discard from the Fragment Offset.
	ipv6FragmentExtHdrFragmentOffsetShift = 3

	// ipv6FragmentExtHdrFlagsidx is the index to the flags field within an
	// IPv6FragmentExtHdr.
	ipv6FragmentExtHdrFlagsIdx = 1

	// ipv6FragmentExtHdrMFlagMask is the mask of the More (M) flag within the
	// flags field of an IPv6FragmentExtHdr.
	ipv6FragmentExtHdrMFlagMask = 1

	// ipv6FragmentExtHdrIdentificationOffset is the offset to the Identification
	// field within an IPv6FragmentExtHdr.
	ipv6FragmentExtHdrIdentificationOffset = 2

	// ipv6FragmentExtHdrPayloadOffset is the offset to the rest of the IPv6
	// payload following the Fragment extension header.
	ipv6FragmentExtHdrPayloadOffset = 6

	// ipv6DestinationOptsExtHdrIdentifer is the identifier of a Destination
	// Options extension header, as per RFC 8200 section 4.6.
	ipv6DestinationOptsExtHdrIdentifer = 60

	// ipv6NoNextHeaderIdentifier is the identifier used to signify the end of an
	// IPv6 payload, as per RFC 8200 section 4.7.
	ipv6NoNextHeaderIdentifier = 59

	// ipv6ExtHdrLenBytesPerUnit is the unit size of an extension header's length
	// field.
	ipv6ExtHdrLenBytesPerUnit = 8

	// ipv6ExtHdrLenBytesExcluded is the number of bytes excluded from an
	// extension header's length field as the Length field does not include the
	// first 8 bytes.
	ipv6ExtHdrLenBytesExcluded = 6
)

// IPv6Payload is the payload of an IPv6 packet.
//
// IPv6Payload holds the bytes of an IPv6 packet following the fixed IPv6
// header. This payload MAY contain IPv6 extension headers before the body
// (upper layer data).
type IPv6Payload []byte

// IPv6PayloadHeader is implemented by the various headers that can be found
// in an IPv6 payload.
//
// These headers include IPv6 extension headers or upper layer data.
type IPv6PayloadHeader interface {
	isIPv6PayloadHeader()
}

// IPv6RawPayloadHeader the remainder of an IPv6 payload after an iterator
// encounters a Next Header field it does not recognize as an IPv6 extension
// header.
type IPv6RawPayloadHeader struct {
	Identifier uint8
	Buf        []byte
}

// isIPv6PayloadHeader implements IPv6PayloadHeader.isIPv6PayloadHeader.
func (IPv6RawPayloadHeader) isIPv6PayloadHeader() {}

// IPv6RoutingExtHdr is a buffer holding the Routing extension header.
type IPv6RoutingExtHdr []byte

// isIPv6PayloadHeader implements IPv6PayloadHeader.isIPv6PayloadHeader.
func (IPv6RoutingExtHdr) isIPv6PayloadHeader() {}

// SegmentsLeft returns the Segments Left field.
func (b IPv6RoutingExtHdr) SegmentsLeft() uint8 {
	return b[ipv6RoutingExtHdrSegmentsLeftIdx]
}

// IPv6FragmentExtHdr is a buffer holding the Fragment extension header.
//
// The buffer MUST be exactly 6 bytes (not including the Next Header and
// Reserved fields).
type IPv6FragmentExtHdr []byte

// isIPv6PayloadHeader implements IPv6PayloadHeader.isIPv6PayloadHeader.
func (IPv6FragmentExtHdr) isIPv6PayloadHeader() {}

// FragmentOffset returns the Fragment Offset field.
//
// This value indicates where the buffer following the Fragment extension header
// starts in the target (reassembled) packet.
func (b IPv6FragmentExtHdr) FragmentOffset() uint16 {
	return binary.BigEndian.Uint16(b[ipv6FragmentExtHdrFragmentOffsetOffset:]) >> ipv6FragmentExtHdrFragmentOffsetShift
}

// More returns the More (M) flag.
//
// This indicates whether any fragments are expected to succeed b.
func (b IPv6FragmentExtHdr) More() bool {
	return b[ipv6FragmentExtHdrFlagsIdx]&ipv6FragmentExtHdrMFlagMask != 0
}

// ID returns the Identification field.
//
// This value is used to uniquely identify the packet, between a
// souce and destination.
func (b IPv6FragmentExtHdr) ID() uint32 {
	return binary.BigEndian.Uint32(b[ipv6FragmentExtHdrIdentificationOffset:])
}

// Payload returns the rest of an IPv6 payload following the Fragment extension
// header.
func (b IPv6FragmentExtHdr) Payload() []byte {
	return b[ipv6FragmentExtHdrPayloadOffset:]
}

// IPv6PayloadIterator is an iterator over the conents of an IPv6 payload.
//
// The IPv6 payload may contain IPv6 extension headers before any upper layer
// data.
//
// Note, between when an IPv6PayloadIterator is obtained and last used, no
// changes to the payload may happen. Doing so may cause undefined and
// unexpected behaviour. It is fine to obtain an IPv6PayloadIterator, iterate
// over the first few headers then modify the backing payload so long as the
// IPv6PayloadIterator obtained before modification is no longer used.
type IPv6PayloadIterator struct {
	// The identifier of the next header to parse.
	nextHdr uint8

	payload *bytes.Buffer

	// Indicates to the iterator that on the next call to Next, it should
	// return the remaining payload as a raw payload without parsing.
	forceRaw bool
}

// MakeIPv6PayloadIterator returns an iterator over the IPv6 payload containing
// extension headers, or a raw payload if the payload cannot be parsed.
func MakeIPv6PayloadIterator(nextHdr uint8, payload []byte, check bool) (IPv6PayloadIterator, error) {
	it := IPv6PayloadIterator{
		nextHdr: nextHdr,
		payload: bytes.NewBuffer(payload),
	}

	if check {
		it2 := it
		// Create a new bytes.Buffer so it.payload is not affected.
		it2.payload = bytes.NewBuffer(payload)

		for {
			if _, done, err := it2.Next(); err != nil || done {
				return it, err
			}
		}
	}

	return it, nil
}

// AsRawHeader returns the remaining payload of i as a raw header and
// completes the iterator.
//
// Calls to Next after calling AsRawHeader on i will indicate that the
// iterator is done.
func (i *IPv6PayloadIterator) AsRawHeader() IPv6RawPayloadHeader {
	buf := i.payload.Bytes()
	i.payload.Reset()
	identifier := i.nextHdr

	// Mark i as done.
	i.nextHdr = ipv6NoNextHeaderIdentifier
	i.forceRaw = false
	return IPv6RawPayloadHeader{Identifier: identifier, Buf: buf}
}

// Next returns the next item in the payload.
//
// If the next item is not a known IPv6 extension header, IPv6RawPayloadHeader
// will be returned with the remaining bytes and next header identifier so the
// caller can handle the (potentially) upper layer protocol.
//
// The return is of the format (payloadItem, done, error). done will be true
// when Next is unable to return anything because the iterator has reached the
// end of the payload, or an error occured.
func (i *IPv6PayloadIterator) Next() (IPv6PayloadHeader, bool, error) {
	// Are we forced to return the iterator as a raw payload?
	if i.forceRaw {
		return i.AsRawHeader(), false, nil
	}

	// Is the header we are parsing a known extension header?
	switch i.nextHdr {
	case ipv6FragmentExtHdrIdentifier:
	case ipv6RoutingExtHdrIdentifier:

	case ipv6NoNextHeaderIdentifier:
		// This indicates the end of the IPv6 payload.
		i.payload.Reset()
		return nil, true, nil

	default:
		// The header we are parsing is not a known extension header. Let the
		// caller determine what to do with the rest of the buffer.
		return i.AsRawHeader(), false, nil
	}

	// We are now parsing a known extension header.

	nextHdr, bytes, err := i.nextHeaderData()
	if err != nil {
		return nil, true, err
	}

	var next IPv6PayloadHeader
	switch i.nextHdr {
	case ipv6RoutingExtHdrIdentifier:
		next = IPv6RoutingExtHdr(bytes)
	case ipv6FragmentExtHdrIdentifier:
		fragmentExtHdr := IPv6FragmentExtHdr(bytes)

		// If the packet is a fragmented packet, do not attempt to parse
		// anything after the fragment extension header as the data following
		// the extension header may not be complete.
		if fragmentExtHdr.More() || fragmentExtHdr.FragmentOffset() != 0 {
			i.forceRaw = true
		}

		next = fragmentExtHdr
	default:
		// Unknown headers should have been handled earlier.
		panic(fmt.Sprintf("unexpected next header value = %d", i.nextHdr))
	}

	i.nextHdr = nextHdr
	return next, false, nil
}

func (i *IPv6PayloadIterator) nextHeaderData() (uint8, []byte, error) {
	nextHdr, err := i.payload.ReadByte()
	if err != nil {
		return 0, nil, fmt.Errorf("error when reading the Next Header field for extension header with id = %d: %w", i.nextHdr, err)
	}

	length, err := i.payload.ReadByte()
	if err != nil {
		return 0, nil, fmt.Errorf("error when reading the Length field for extension header with id = %d: %w", i.nextHdr, err)
	}

	bytesLen := int(length)*ipv6ExtHdrLenBytesPerUnit + ipv6ExtHdrLenBytesExcluded
	bytes := i.payload.Next(bytesLen)
	if n := len(bytes); n != bytesLen {
		return 0, nil, fmt.Errorf("read %d out of %d extension header data bytes (length = %d) for header with id = %d: %w", n, bytesLen, length, i.nextHdr, io.EOF)
	}

	return nextHdr, bytes, nil
}
