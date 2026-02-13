package config

import (
	"net/netip"
	"sort"
)

// ExcludePrefixes removes exclude prefixes from base prefixes and returns the
// remaining set. For example, excluding 10.0.0.0/8 from 0.0.0.0/0 returns a
// set of prefixes covering everything except 10.0.0.0/8.
func ExcludePrefixes(base []netip.Prefix, exclude []netip.Prefix) []netip.Prefix {
	result := make([]netip.Prefix, len(base))
	copy(result, base)

	for _, ex := range exclude {
		var next []netip.Prefix
		for _, p := range result {
			next = append(next, subtractPrefix(p, ex)...)
		}
		result = next
	}

	sort.Slice(result, func(i, j int) bool {
		ai, aj := result[i].Addr(), result[j].Addr()
		if ai != aj {
			return ai.Less(aj)
		}
		return result[i].Bits() < result[j].Bits()
	})

	return result
}

// subtractPrefix removes the "remove" prefix from "from" and returns the
// remaining prefixes. If they don't overlap, returns "from" unchanged.
func subtractPrefix(from, remove netip.Prefix) []netip.Prefix {
	if !from.Overlaps(remove) {
		return []netip.Prefix{from}
	}
	if remove.Bits() <= from.Bits() && remove.Contains(from.Addr()) {
		return nil
	}

	bits := from.Bits() + 1
	if from.Addr().Is4() && bits > 32 {
		return []netip.Prefix{from}
	}
	if from.Addr().Is6() && bits > 128 {
		return []netip.Prefix{from}
	}

	left, right := splitPrefix(from)

	var result []netip.Prefix
	result = append(result, subtractPrefix(left, remove)...)
	result = append(result, subtractPrefix(right, remove)...)
	return result
}

// splitPrefix splits a prefix into two halves with one more bit of prefix length.
func splitPrefix(p netip.Prefix) (netip.Prefix, netip.Prefix) {
	bits := p.Bits() + 1
	addr := p.Addr()

	left := netip.PrefixFrom(addr, bits)

	if addr.Is4() {
		raw := addr.As4()
		byteIndex := (bits - 1) / 8
		bitIndex := 7 - ((bits - 1) % 8)
		raw[byteIndex] |= 1 << bitIndex
		right := netip.PrefixFrom(netip.AddrFrom4(raw), bits)
		return left, right
	}

	raw := addr.As16()
	byteIndex := (bits - 1) / 8
	bitIndex := 7 - ((bits - 1) % 8)
	raw[byteIndex] |= 1 << bitIndex
	right := netip.PrefixFrom(netip.AddrFrom16(raw), bits)
	return left, right
}
