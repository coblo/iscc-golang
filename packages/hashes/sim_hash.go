package hashes

import (
	"encoding/binary"
	"errors"
)

func SimilarityHash(hashDigests [][]byte) ([]byte, error) {
	nBytes := len(hashDigests[0])
	nBits := uint(nBytes * 8)
	vector := make([]uint64, nBits)
	for _, digest := range hashDigests {
		if len(digest) != nBytes {
			return nil, errors.New("Digests lengths not consistent")
		}

		// pad digest
		digest = append(make([]byte, 8-len(digest)), digest...)
		h := binary.BigEndian.Uint64(digest)

		for i := uint(0); i < nBits; i++ {
			vector[i] += h & 1
			h >>= 1
		}
	}

	minfeatures := uint64((float64(len(hashDigests)) / 2) + 0.5)
	sHash := uint64(0)

	for i := uint(0); i < nBits; i++ {
		if vector[i] >= minfeatures {
			sHash |= 1 << uint(i)
		}
	}
	simHash := make([]byte, 8)
	binary.BigEndian.PutUint64(simHash, sHash)
	// return resized simhash
	return simHash[8-nBytes:], nil
}
