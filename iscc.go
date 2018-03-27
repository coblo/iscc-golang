package iscc

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"github.com/OneOfOne/xxhash"
	"github.com/coblo/iscc-golang/packages/base58"
	"github.com/coblo/iscc-golang/packages/cdc"
	"github.com/coblo/iscc-golang/packages/hashes"
	"github.com/pkg/errors"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"strings"
)

type ISCC struct {
	Meta     [11]byte
	Partial  bool
	Gmt      int
	Content  [11]byte
	Data     [11]byte
	Instance [11]byte
}

const (
	INPUT_TRIM             = 128
	WINDOW_SIZE_MID        = 4
	WINDOW_SIZE_CID_T      = 5
	HEAD_MID          byte = '\x00'
	HEAD_CID_T        byte = '\x10'
	HEAD_CID_T_PCF    byte = '\x11'
	HEAD_CID_I        byte = '\x12'
	HEAD_CID_I_PCF    byte = '\x13'
	HEAD_CID_A             = '\x14'
	HEAD_CID_A_PCF         = '\x15'
	HEAD_CID_V             = '\x16'
	HEAD_CID_V_PCF         = '\x17'
	HEAD_CID_M             = '\x18'
	HEAD_CID_M_PCF         = '\x19'
	HEAD_DID          byte = '\x20'
	HEAD_IID          byte = '\x30'
)

func MetaId(title, extra string, version int) (metaId, processedTitle, processedExtra string, err error) {

	// 1. verify version is supported
	if version != 1 {
		return "", "", "", errors.New("Only version 1 is supported")
	}

	// 2. & 3. Pre normalization & trimming
	processedTitle = textTrim(textPreNormalize(title))
	processedExtra = textTrim(textPreNormalize(extra))

	// 4. Concatenate
	concat := strings.TrimSpace(processedTitle + "\u0020" + processedExtra)

	// 5. Normalization
	normalized := textNormalize(concat)

	// 6. Create list of n-grams
	nGramWindows, err := createNGramWindowsLetterWise(normalized, WINDOW_SIZE_MID)
	if err != nil {
		return
	}

	// 7. create xxhash64 digest
	hash := xxhash.New64()
	hashDigests := make([][]byte, len(nGramWindows))
	for i, window := range nGramWindows {
		hash.Write(window)
		hashDigests[i] = hash.Sum(nil)
		hash.Reset()
	}

	// 8. Apply similarity hash
	simhashDigest, err := hashes.SimilarityHash(hashDigests)
	if err != nil {
		return
	}
	// 9. prepend header-byte
	meta_id_digest := append([]byte{HEAD_MID}, simhashDigest...)

	// 10. encode with base58-iscc
	metaId, err = base58.Encode(meta_id_digest)

	// 11. Return encoded Meta-ID, trimmed `title` and trimmed `extra` data.
	return
}

func ContentIdText(text string, partial bool) (string, error) {
	// 1. & 2. Pre-normalize and normalize
	text = textNormalize(textPreNormalize(text))

	// 3. Split to words
	w := strings.Split(text, " ")

	// 4. create 5 word shingles
	wordNGrams, err := createNGramWindowsWordWise(w, WINDOW_SIZE_CID_T)
	if err != nil {
		return "", err
	}
	shingles := make([]string, len(wordNGrams))
	for i, words := range wordNGrams {
		shingles[i] = strings.Join(words, "\u0020")
	}

	// 5. create 32-bit features with xxHash32
	features := make([]uint32, len(shingles))
	for i, window := range shingles {
		features[i] = xxhash.Checksum32([]byte(window))
	}

	// 6. Apply minimum-hash
	mHash := hashes.MinHash(features)

	// 7. & 8 Collect least significant bits and create 64-bit digests
	lsb := getLSBDigests(mHash)

	// 9. Apply simhash to digests
	simhashDigest, err := hashes.SimilarityHash(lsb)

	// 10. & 11. prepend component header, encode and return
	if partial {
		return base58.Encode(append([]byte{HEAD_CID_T_PCF}, simhashDigest...))
	} else {
		return base58.Encode(append([]byte{HEAD_CID_T}, simhashDigest...))
	}
}

func ContentIdImage(img image.Image, partial bool) (contentId string, err error) {
	// 1. Normalize image to 2-dimensional pixel array
	grayImage, err := imageNormalize(img)

	// 2. Calculate image hash
	hashDigest := hashes.ImageHash(*grayImage)
	contentIdImage := make([]byte, 8)
	binary.BigEndian.PutUint64(contentIdImage, hashDigest)

	// 3. Prepend the 1-byte component header
	if partial {
		contentIdImage = append([]byte{HEAD_CID_I_PCF}, contentIdImage...)
	} else {
		contentIdImage = append([]byte{HEAD_CID_I}, contentIdImage...)
	}

	// 4. Encode and return
	return base58.Encode(contentIdImage)
}

func ContentIdImageFromFile(reader io.Reader, partial bool) (contentId string, err error) {
	img, _, err := image.Decode(reader)
	if err != nil {
		return
	}
	return ContentIdImage(img, partial)
}

func ContentIdMixed(cids []string, partial bool) (string, error) {
	// 1. Decode CIDs
	decoded := make([][]byte, len(cids))
	var err error
	for i := range decoded {
		decoded[i], err = base58.Decode(cids[i])
		if err != nil {
			return "", err
		}
	}

	// 2. Extract first 8-bytes
	for i := range decoded {
		decoded[i] = decoded[i][:8]
	}

	// 3. Apply Similarity hash
	simhashDigest, err := hashes.SimilarityHash(decoded)
	if err != nil {
		return "", err
	}

	// 4. & 5. Prepend component header, encode and return
	if partial {
		return base58.Encode(append([]byte{HEAD_CID_M_PCF}, simhashDigest...))
	} else {
		return base58.Encode(append([]byte{HEAD_CID_M}, simhashDigest...))
	}
}

func DataId(r io.Reader) (string, error) {
	// 1 & 2. xxHash32 over CDC
	features := cdc.GetHashedCDC(r)

	// 3. Apply minimum hash
	mhash := hashes.MinHash(features)

	// 4. & 5. Collect lsb and create 64-bit digests
	lsb := getLSBDigests(mhash)

	// 6. Apply simhash
	simHash, err := hashes.SimilarityHash(lsb)
	if err != nil {
		return "", err
	}

	// 7. Prepend 1-byte header
	data_id_digest := append([]byte{HEAD_DID}, simHash...)

	// 8. encode and return
	return base58.Encode(data_id_digest)
}

func InstanceId(r io.Reader) (code string, hex_hash string) {
	buffer := make([]byte, 64000)

	var leafNodeDigests [][32]byte
	// 1. Split int 64 kB chunks
	for {
		n, _ := r.Read(buffer)
		if n == 0 {
			break
		}
		// 2. for each chunk calc sha256d  of the concatenation of a 0x00 byte and the chunk
		leafNodeDigests = append(leafNodeDigests, doubleSha256(append([]byte{'\x00'}, buffer[:n]...)))
	}
	// 3. & 4. Apply topHash
	topHashDigest := topHash(leafNodeDigests)

	// 5. & 6. Trim the tophash to the first 8 bytes and prepend component header
	instanceIdDigest := append([]byte{HEAD_IID}, topHashDigest[:8]...)
	// 7. encode instance id
	code, _ = base58.Encode(instanceIdDigest)
	// 8. Hex encode the tophash
	hex_hash = hex.EncodeToString(topHashDigest[:])
	// 9. return the instance id and the hex encoded tophash
	return
}

func createNGramWindowsLetterWise(text string, width int) ([][]byte, error) {
	if width < 2 {
		return nil, errors.New("Sliding window width must be 2 or bigger")
	}
	chars := []rune(text)

	// if the window width exceeds the string length use only one ngram
	if width > len(chars) {
		return [][]byte{[]byte(text)}, nil
	}

	windows := make([][]byte, len(chars)-width+1)
	for i := range windows {
		windows[i] = []byte(string(chars[i : i+width]))
	}
	return windows, nil
}

// TODO build interface to combine those 2 methods
func createNGramWindowsWordWise(words []string, width int) ([][]string, error) {
	if width < 2 {
		return nil, errors.New("Sliding window width must be 2 or bigger")
	}

	// if the window width exceeds the string length use only one ngram
	if width > len(words) {
		return [][]string{words}, nil
	}

	windows := make([][]string, len(words)-width+1)
	for i := range windows {
		windows[i] = words[i : i+width]
	}
	return windows, nil
}

func doubleSha256(data []byte) (res [32]byte) {
	res = sha256.Sum256(data)
	return sha256.Sum256(res[:])

}

func topHash(hashes [][32]byte) [32]byte {
	size := len(hashes)
	if len(hashes) == 1 {
		return hashes[0]
	}

	pairwiseHashed := make([][32]byte, (size/2 + (size % 2)))
	for i := range pairwiseHashed {
		pairwiseHashed[i] = hashInnerNodes(hashes[i*2], hashes[(i*2)+1])
	}
	if size%2 == 1 {
		pairwiseHashed[len(pairwiseHashed)-1] = hashInnerNodes(hashes[size-1], hashes[size-1])
	}
	return topHash(pairwiseHashed)
}

func hashInnerNodes(h1, h2 [32]byte) [32]byte {
	concat := make([]byte, 0, 65)
	concat = append([]byte{'\x01'}, h1[:]...)
	concat = append(concat, h2[:]...)
	return doubleSha256(concat)
}

func getLSBDigests(mhash [128]uint32) [][]byte {
	var a, b uint64
	for i, x := range mhash[:64] {
		if (x & 1) == 1 {
			a += 1 << uint8(63-i)
		}
	}
	for i, x := range mhash[64:] {
		if (x & 1) == 1 {
			b += 1 << uint8(63-i)
		}
	}

	aArray := make([]byte, 8)
	bArray := make([]byte, 8)
	binary.BigEndian.PutUint64(aArray, a)
	binary.BigEndian.PutUint64(bArray, b)

	return [][]byte{aArray, bArray}
}
