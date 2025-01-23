package tool

import (
	"github.com/coordinate/alist/internal/errs"
)

var (
	Tools = make(map[string]Tool)
)

func RegisterTool(tool Tool) {
	for _, ext := range tool.AcceptedExtensions() {
		Tools[ext] = tool
	}
}

func GetArchiveTool(ext string) (Tool, error) {
	t, ok := Tools[ext]
	if !ok {
		return nil, errs.UnknownArchiveFormat
	}
	return t, nil
}
