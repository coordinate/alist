package LenovoNasShare

import (
	"context"
	"net/http"

	"github.com/go-resty/resty/v2"

	"github.com/coordinate/alist/internal/driver"
	"github.com/coordinate/alist/internal/errs"
	"github.com/coordinate/alist/internal/model"
	"github.com/coordinate/alist/pkg/utils"
)

type LenovoNasShare struct {
	model.Storage
	Addition
	stoken string
}

func (d *LenovoNasShare) Config() driver.Config {
	return config
}

func (d *LenovoNasShare) GetAddition() driver.Additional {
	return &d.Addition
}

func (d *LenovoNasShare) Init(ctx context.Context) error {
	if d.Host == "" {
		d.Host = "https://siot-share.lenovo.com.cn"
	}
	query := map[string]string{
		"code":     d.ShareId,
		"password": d.SharePwd,
	}
	resp, err := d.request(d.Host+"/oneproxy/api/share/v1/access", http.MethodGet, func(req *resty.Request) {
		req.SetQueryParams(query)
	}, nil)
	if err != nil {
		return err
	}
	d.stoken = utils.Json.Get(resp, "data", "stoken").ToString()
	return nil
}

func (d *LenovoNasShare) Drop(ctx context.Context) error {
	return nil
}

func (d *LenovoNasShare) List(ctx context.Context, dir model.Obj, args model.ListArgs) ([]model.Obj, error) {
	files := make([]File, 0)

	var resp Files
	query := map[string]string{
		"code":   d.ShareId,
		"num":    "5000",
		"stoken": d.stoken,
		"path":   dir.GetPath(),
	}
	_, err := d.request(d.Host+"/oneproxy/api/share/v1/files", http.MethodGet, func(req *resty.Request) {
		req.SetQueryParams(query)
	}, &resp)
	if err != nil {
		return nil, err
	}
	files = append(files, resp.Data.List...)

	return utils.SliceConvert(files, func(src File) (model.Obj, error) {
		return src, nil
	})
}

func (d *LenovoNasShare) Link(ctx context.Context, file model.Obj, args model.LinkArgs) (*model.Link, error) {
	query := map[string]string{
		"code":   d.ShareId,
		"stoken": d.stoken,
		"path":   file.GetPath(),
	}
	resp, err := d.request(d.Host+"/oneproxy/api/share/v1/file/link", http.MethodGet, func(req *resty.Request) {
		req.SetQueryParams(query)
	}, nil)
	if err != nil {
		return nil, err
	}
	downloadUrl := d.Host + "/oneproxy/api/share/v1/file/download?code=" + d.ShareId + "&dtoken=" + utils.Json.Get(resp, "data", "param", "dtoken").ToString()

	link := model.Link{
		URL: downloadUrl,
		Header: http.Header{
			"Referer": []string{"https://siot-share.lenovo.com.cn"},
		},
	}
	return &link, nil
}

func (d *LenovoNasShare) MakeDir(ctx context.Context, parentDir model.Obj, dirName string) (model.Obj, error) {
	return nil, errs.NotImplement
}

func (d *LenovoNasShare) Move(ctx context.Context, srcObj, dstDir model.Obj) (model.Obj, error) {
	return nil, errs.NotImplement
}

func (d *LenovoNasShare) Rename(ctx context.Context, srcObj model.Obj, newName string) (model.Obj, error) {
	return nil, errs.NotImplement
}

func (d *LenovoNasShare) Copy(ctx context.Context, srcObj, dstDir model.Obj) (model.Obj, error) {
	return nil, errs.NotImplement
}

func (d *LenovoNasShare) Remove(ctx context.Context, obj model.Obj) error {
	return errs.NotImplement
}

func (d *LenovoNasShare) Put(ctx context.Context, dstDir model.Obj, stream model.FileStreamer, up driver.UpdateProgress) (model.Obj, error) {
	return nil, errs.NotImplement
}

var _ driver.Driver = (*LenovoNasShare)(nil)
