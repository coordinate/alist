package common

import (
	stdpath "path"

	"github.com/coordinate/alist/internal/conf"
	"github.com/coordinate/alist/internal/model"
	"github.com/coordinate/alist/internal/setting"
	"github.com/coordinate/alist/internal/sign"
)

func Sign(obj model.Obj, parent string, encrypt bool) string {
	if obj.IsDir() || (!encrypt && !setting.GetBool(conf.SignAll)) {
		return ""
	}
	return sign.Sign(stdpath.Join(parent, obj.GetName()))
}
