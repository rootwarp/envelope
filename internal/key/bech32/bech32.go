// Copyright (c) 2017 Takatoshi Nakagawa
// Copyright (c) 2019 The age Authors
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

// Vendored because filippo.io/age/internal/bech32 is an internal package and age
// exports no path to the X25519 scalar. This copy matches age's fork, which removed
// BIP-173's 90-character length limit. Decoding the age identity encoding is a
// dependency on the C2SP age specification, not on a Go API promise. See ADR-0005
// and FR-32.

// Package bech32 is a modified version of the reference implementation of BIP173.
package bech32

import (
	"fmt"
	"strings"
)

var charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

var generator = []uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}

func polymod(values []byte) uint32 {
	chk := uint32(1)
	for _, v := range values {
		top := chk >> 25
		chk = (chk & 0x1ffffff) << 5
		chk = chk ^ uint32(v)
		for i := range 5 {
			bit := top >> i & 1
			if bit == 1 {
				chk ^= generator[i]
			}
		}
	}
	return chk
}

func hrpExpand(hrp string) []byte {
	h := []byte(strings.ToLower(hrp))
	var ret []byte
	for _, c := range h {
		ret = append(ret, c>>5)
	}
	ret = append(ret, 0)
	for _, c := range h {
		ret = append(ret, c&31)
	}
	return ret
}

func verifyChecksum(hrp string, data []byte) bool {
	return polymod(append(hrpExpand(hrp), data...)) == 1
}

func convertBits(data []byte, frombits, tobits byte, pad bool) ([]byte, error) {
	var ret []byte
	acc := uint32(0)
	bits := byte(0)
	maxv := byte(1<<tobits - 1)
	for idx, value := range data {
		if value>>frombits != 0 {
			return nil, fmt.Errorf("invalid data range: data[%d]=%d (frombits=%d)", idx, value, frombits)
		}
		acc = acc<<frombits | uint32(value)
		bits += frombits
		for bits >= tobits {
			bits -= tobits
			ret = append(ret, byte(acc>>bits)&maxv)
		}
	}
	if pad {
		if bits > 0 {
			ret = append(ret, byte(acc<<(tobits-bits))&maxv)
		}
	} else if bits >= frombits {
		return nil, fmt.Errorf("illegal zero padding")
	} else if byte(acc<<(tobits-bits))&maxv != 0 {
		return nil, fmt.Errorf("non-zero padding")
	}
	return ret, nil
}

// Decode decodes a Bech32 string. If the string is uppercase, the HRP will be uppercase.
func Decode(s string) (hrp string, data []byte, err error) {
	if strings.ToLower(s) != s && strings.ToUpper(s) != s {
		return "", nil, fmt.Errorf("mixed case")
	}
	pos := strings.LastIndex(s, "1")
	if pos < 1 || pos+7 > len(s) {
		return "", nil, fmt.Errorf("separator '1' at invalid position: pos=%d, len=%d", pos, len(s))
	}
	hrp = s[:pos]
	for p, c := range hrp {
		if c < 33 || c > 126 {
			return "", nil, fmt.Errorf("invalid character human-readable part: s[%d]=%d", p, c)
		}
	}
	s = strings.ToLower(s)
	for p, c := range s[pos+1:] {
		d := strings.IndexRune(charset, c)
		if d == -1 {
			return "", nil, fmt.Errorf("invalid character data part: s[%d]=%v", p, c)
		}
		data = append(data, byte(d))
	}
	if !verifyChecksum(hrp, data) {
		return "", nil, fmt.Errorf("invalid checksum")
	}
	data, err = convertBits(data[:len(data)-6], 5, 8, false)
	if err != nil {
		return "", nil, err
	}
	return hrp, data, nil
}
