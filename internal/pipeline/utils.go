package pipeline

import (
	"strings"
)

func headerValue(headers map[string]string, key string) string {
	if headers == nil {
		return ""
	}
	if v, ok := headers[strings.ToLower(key)]; ok {
		return strings.TrimSpace(v)
	}
	for k, v := range headers {
		if strings.EqualFold(k, key) {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func isPublicPath(path string, publicPaths []string) bool {
	for _, publicPath := range publicPaths {
		if strings.HasSuffix(publicPath, "/") {
			if strings.HasPrefix(path, publicPath) {
				return true
			}
			continue
		}
		if path == publicPath {
			return true
		}
	}
	return false
}
