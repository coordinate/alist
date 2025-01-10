package encrypt

import (
	"fmt"
	"hash/fnv"
	stdurl "net/url"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/fanjindong/go-cache"
)

// ****************************************************
var RawURLCache = cache.NewMemCache(cache.WithShards(128))

func DecryptFileName(fileName string) string {
	extension := strings.ToUpper(filepath.Ext(fileName))
	nameWithoutExt := fileName[:len(fileName)-len(extension)]
	// if len(fileName) != 21 {
	if extension != ".MP4" && extension != ".MKV" {
		return fileName
	}
	// password := "111500"
	// encryptFlow, _ := NewAesCTR(password, 1)
	passwdOutward := "1957a5abbad658aaae6d3a38ce66f5f2" // encryptFlow.passwdOutward
	mixBase64 := NewMixBase64(passwdOutward, "mix64")
	length := len(nameWithoutExt)
	crc6Check := nameWithoutExt[length-1]
	subEncName := nameWithoutExt[0 : length-1]
	crc := NewCRCn(6, 0, 0)
	crc6Bit := crc.Checksum([]byte(subEncName + passwdOutward))
	// console.log(subEncName, MixBase64.getSourceChar(crc6Bit), crc6Check)
	if GetSourceChar(crc6Bit) != crc6Check {
		return fileName
	}
	decoded, _ := mixBase64.Decode(subEncName)
	return string(decoded)
}

func Redirect(host string, reqPath string, realUrl string, fileSize int64) string {
	if !strings.Contains(reqPath, "classmap/") {
		return realUrl
	}
	value := fmt.Sprintf("%d%s", fileSize, realUrl)
	hash := fnv.New64a()
	hash.Write([]byte(value))
	key := strconv.FormatUint(hash.Sum64(), 10)
	// key := uuid.New().String()
	// realUrl, ok := RawURLCache.Get(key)
	RawURLCache.Set(key, value)
	p := stdurl.QueryEscape(reqPath)
	// print(p)
	return fmt.Sprintf(
		"http://%s/redirect/%s?decode=1&lastUrl=%s",
		host,
		key,
		p,
	)
}

// ****************************************************
