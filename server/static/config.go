package static

import (
	"strings"

	"github.com/coordinate/alist/internal/conf"
	"github.com/coordinate/alist/pkg/utils"
)

type SiteConfig struct {
	BasePath string
	Cdn      string
}

func getSiteConfig() SiteConfig {
	siteConfig := SiteConfig{
		BasePath: conf.URL.Path,
		Cdn:      strings.ReplaceAll(strings.TrimSuffix(conf.Conf.Cdn, "/"), "$version", conf.WebVersion),
	}
	if siteConfig.BasePath != "" {
		siteConfig.BasePath = utils.FixAndCleanPath(siteConfig.BasePath)
	}
	if siteConfig.Cdn == "" {
		siteConfig.Cdn = strings.TrimSuffix(siteConfig.BasePath, "/")
	}
	return siteConfig
}
