package search

import (
	_ "github.com/coordinate/alist/internal/search/bleve"
	_ "github.com/coordinate/alist/internal/search/db"
	_ "github.com/coordinate/alist/internal/search/db_non_full_text"
	_ "github.com/coordinate/alist/internal/search/meilisearch"
)
