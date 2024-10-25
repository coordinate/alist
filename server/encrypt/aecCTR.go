package encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/pbkdf2"
)

type AesCTR struct {
	password      string
	sizeSalt      string
	passwdOutward string
	key           []byte
	iv            []byte
	soureIv       []byte
	cipher        cipher.Stream
}

func NewAesCTR(password string, sizeSalt int) (*AesCTR, error) {
	ac := &AesCTR{
		password: password,
		sizeSalt: fmt.Sprintf("%d", sizeSalt),
	}

	// Check base64
	if len(password) != 32 {
		salt := []byte("AES-CTR") // The salt used in the original Node.js code
		iterations := 1000        // The number of iterations
		keyLength := 16           // Desired key length in bytes
		// Generate the PBKDF2 key
		key := pbkdf2.Key([]byte(password), salt, iterations, keyLength, sha256.New)
		// Convert the key to a hex string
		ac.passwdOutward = hex.EncodeToString(key)
	}

	// Create AES-CTR key
	passwdSalt := ac.passwdOutward + ac.sizeSalt
	hashMD5 := md5Sum(passwdSalt)
	ac.key = hashMD5[:16] // AES-128 requires a 16-byte key
	ac.iv = md5Sum(ac.sizeSalt)[:16]

	// Copy to soureIv
	ac.soureIv = make([]byte, len(ac.iv))
	copy(ac.soureIv, ac.iv)
	return ac, nil
}

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
	ac.iv = make([]byte, len(ac.soureIv))
	copy(ac.iv, ac.soureIv)

	increment := position / 16
	ac.incrementIV(increment)

	ac.createCipher()

	offset := position % 16
	buffer := make([]byte, offset)
	ac.Encrypt(buffer) // To advance the stream
}

func (ac *AesCTR) incrementIV(increment int) {
	const maxUint32 = 0xffffffff
	incrementBig := increment / maxUint32
	incrementLittle := increment % maxUint32

	// Split the 128 bits IV into 4 numbers, 32 bits each
	overflow := 0
	for i := 0; i < 4; i++ {
		num := binary.BigEndian.Uint32(ac.iv[12-4*i : 16-4*i])
		inc := overflow
		if i == 0 {
			inc += incrementLittle
		}
		if i == 1 {
			inc += incrementBig
		}
		num += uint32(inc)
		overflow = int(num >> 32)
		binary.BigEndian.PutUint32(ac.iv[12-4*i:16-4*i], uint32(num))
	}
}

func md5Sum(data string) []byte {
	h := md5.New()
	h.Write([]byte(data))
	return h.Sum(nil)
}
