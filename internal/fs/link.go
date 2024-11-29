package fs

import (
	"context"
	"strings"

	"github.com/coordinate/alist/internal/model"
	"github.com/coordinate/alist/internal/op"
	"github.com/coordinate/alist/server/common"
	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
)

func link(ctx context.Context, path string, args model.LinkArgs) (*model.Link, model.Obj, error) {
	storage, actualPath, err := op.GetStorageAndActualPath(path)
	if err != nil {
		return nil, nil, errors.WithMessage(err, "failed get storage")
	}
	l, obj, err := op.Link(ctx, storage, actualPath, args)
	if err != nil {
		return nil, nil, errors.WithMessage(err, "failed link")
	}
	if l.URL != "" && !strings.HasPrefix(l.URL, "http://") && !strings.HasPrefix(l.URL, "https://") {
		if c, ok := ctx.(*gin.Context); ok {
			l.URL = common.GetApiUrl(c.Request) + l.URL
		}
	}
	return l, obj, nil
}
