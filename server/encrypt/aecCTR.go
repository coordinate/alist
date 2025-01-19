package encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"math"
	// "github.com/CrackedPoly/AES-implementation-in-Golang/src/aes"
)

// ****************************************************

type AesCTR struct {
	password      string
	sizeSalt      string
	passwdOutward string
	key           []byte
	iv            []byte
	sourceIv      []byte
	cipher        cipher.Stream
}

const MAX_UINT32 = 0xffffffff

func NewAesCTR(password string, sizeSalt int) (*AesCTR, error) {
	ac := &AesCTR{
		password: password,
		sizeSalt: fmt.Sprintf("%d", sizeSalt),
	}

	// Check base64
	// if len(password) != 32 {
	// 	salt := []byte("AES-CTR") // The salt used in the original Node.js code
	// 	iterations := 1000        // The number of iterations
	// 	keyLength := 16           // Desired key length in bytes
	// 	// Generate the PBKDF2 key
	// 	key := pbkdf2.Key([]byte(password), salt, iterations, keyLength, sha256.New)
	// 	// Convert the key to a hex string
	// 	ac.passwdOutward = hex.EncodeToString(key)
	// }
	ac.passwdOutward = "1957a5abbad658aaae6d3a38ce66f5f2"

	// Create AES-CTR key
	passwdSalt := ac.passwdOutward + ac.sizeSalt
	hashMD5 := md5Sum(passwdSalt)
	ac.key = hashMD5[:16] // AES-128 requires a 16-byte key
	ac.iv = md5Sum(ac.sizeSalt)[:16]

	// Copy to sourceIv
	ac.sourceIv = make([]byte, len(ac.iv))
	copy(ac.sourceIv, ac.iv)
	return ac, nil
}

func md5Sum(str string) []byte {
	checksum := md5.Sum([]byte(str))
	return checksum[0:]
}

// func md5Sum(data string) []byte {
// 	h := md5.New()
// 	h.Write([]byte(data))
// 	return h.Sum(nil)
// }

func (ac *AesCTR) createCipher() error {
	block, err := aes.NewCipher(ac.key)
	if err != nil {
		return err
	}
	ac.cipher = cipher.NewCTR(block, ac.iv)
	return nil
}

func (ac *AesCTR) Encrypt(message []byte) []byte {
	if ac.cipher == nil {
		ac.createCipher()
	}
	out := make([]byte, len(message))
	ac.cipher.XORKeyStream(out, message)
	return out
}

func (ac *AesCTR) Decrypt(message []byte) []byte {
	return ac.Encrypt(message) // Decryption is the same as encryption in CTR mode
}

func (ac *AesCTR) SetPosition(position int) {
	ac.iv = make([]byte, len(ac.sourceIv))
	copy(ac.iv, ac.sourceIv)

	increment := position / 16
	ac.incrementIV(uint32(increment))

	ac.createCipher()

	offset := position % 16
	buffer := make([]byte, offset)
	ac.Encrypt(buffer) // To advance the stream
}

func (ac *AesCTR) incrementIV(increment uint32) {
	incrementBig := increment / MAX_UINT32
	incrementLittle := increment % MAX_UINT32
	overflow := uint32(0)
	for idx := 0; idx < 4; idx++ {
		offset := 12 - idx*4
		num := uint64(binary.BigEndian.Uint32(ac.iv[offset : offset+4]))
		inc := overflow
		if idx == 0 {
			inc += incrementLittle
		}
		if idx == 1 {
			inc += incrementBig
		}
		num += uint64(inc)
		numBig := uint32(math.Floor(float64(num) / MAX_UINT32))
		numLittle := uint32(num%MAX_UINT32) - numBig
		overflow = numBig
		binary.BigEndian.PutUint32(ac.iv[offset:offset+4], numLittle)
	}
}
