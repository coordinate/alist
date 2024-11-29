package ftp

import (
	"github.com/axgle/mahonia"
	"github.com/coordinate/alist/internal/driver"
	"github.com/coordinate/alist/internal/op"
)

func encode(str string, encoding string) string {
	if encoding == "" {
		return str
	}
	encoder := mahonia.NewEncoder(encoding)
	return encoder.ConvertString(str)
}

func decode(str string, encoding string) string {
	if encoding == "" {
		return str
	}
	decoder := mahonia.NewDecoder(encoding)
	return decoder.ConvertString(str)
}

type Addition struct {
	Address  string `json:"address" required:"true"`
	Encoding string `json:"encoding" required:"true"`
	Username string `json:"username" required:"true"`
	Password string `json:"password" required:"true"`
	driver.RootPath
}

var config = driver.Config{
	Name:        "FTP",
	LocalSort:   true,
	OnlyLocal:   true,
	DefaultRoot: "/",
}

func init() {
	op.RegisterDriver(func() driver.Driver {
		return &FTP{}
	})
}
