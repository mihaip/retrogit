package githop

import (
	"bufio"
	"bytes"
	"net/http"
	"net/http/httputil"
	"strings"

	"appengine"
	"appengine/memcache"
)

// Simple http.RoundTripper implementation which wraps an existing transport and
// caches all responses for GET and HEAD requests. Meant to speed up the
// iteration cycle during development.
type CachingTransport struct {
	Transport http.RoundTripper
	Context   appengine.Context
}

func (t *CachingTransport) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	if req.Method != "GET" && req.Method != "HEAD" {
		return t.Transport.RoundTrip(req)
	}
	cacheKey := "CachingTransport:" + req.URL.String() + "#"
	authorizationHeaders, ok := req.Header["Authorization"]
	if ok {
		cacheKey += strings.Join(authorizationHeaders, "#")
	} else {
		cacheKey += "Unauthorized"
	}

	cachedRespItem, err := memcache.Get(t.Context, cacheKey)
	if err != nil && err != memcache.ErrCacheMiss {
		t.Context.Errorf("Error getting cached response: %v", err)
		return t.Transport.RoundTrip(req)
	}
	if err == nil {
		cacheRespBuffer := bytes.NewBuffer(cachedRespItem.Value)
		resp, err := http.ReadResponse(bufio.NewReader(cacheRespBuffer), req)
		if err == nil {
			return resp, nil
		} else {
			t.Context.Errorf("Error readings bytes for cached response: %v", err)
		}
	}
	resp, err = t.Transport.RoundTrip(req)
	if err != nil {
		return
	}
	respBytes, err := httputil.DumpResponse(resp, true)
	if err != nil {
		t.Context.Errorf("Error dumping bytes for cached response: %v", err)
		return resp, nil
	}
	err = memcache.Set(t.Context, &memcache.Item{Key: cacheKey, Value: respBytes})
	if err != nil {
		t.Context.Errorf("Error setting cached response: %v", err)
	}
	return resp, nil
}
