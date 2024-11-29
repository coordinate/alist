package middlewares

import (
	"github.com/coordinate/alist/internal/conf"
	"github.com/coordinate/alist/internal/errs"
	"github.com/coordinate/alist/internal/setting"
	"github.com/coordinate/alist/server/common"
	"github.com/gin-gonic/gin"
)

func SearchIndex(c *gin.Context) {
	mode := setting.GetStr(conf.SearchIndex)
	if mode == "none" {
		common.ErrorResp(c, errs.SearchNotAvailable, 500)
		c.Abort()
	} else {
		c.Next()
	}
}
