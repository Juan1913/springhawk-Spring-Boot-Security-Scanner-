package utils

// MurmurHash2 implements the 32-bit MurmurHash2 algorithm used by Shodan/Censys
// for favicon fingerprinting. Spring Boot's default favicon has a known hash.
func MurmurHash2(data []byte) int32 {
	const m uint32 = 0x5bd1e995
	const r = 24
	seed := uint32(0)
	h := seed ^ uint32(len(data))

	for len(data) >= 4 {
		k := uint32(data[0]) | uint32(data[1])<<8 | uint32(data[2])<<16 | uint32(data[3])<<24
		k *= m
		k ^= k >> r
		k *= m
		h *= m
		h ^= k
		data = data[4:]
	}

	switch len(data) {
	case 3:
		h ^= uint32(data[2]) << 16
		fallthrough
	case 2:
		h ^= uint32(data[1]) << 8
		fallthrough
	case 1:
		h ^= uint32(data[0])
		h *= m
	}

	h ^= h >> 13
	h *= m
	h ^= h >> 15
	return int32(h)
}
