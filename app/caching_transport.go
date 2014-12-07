package retrogit

import (
	"bufio"
	"bytes"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

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
	t.Context.Infof("Fetching %s", req.URL)
	resp, err = t.Transport.RoundTrip(req)
	if err != nil || resp.StatusCode != 200 {
		return
	}
	respBytes, err := httputil.DumpResponse(resp, true)
	if err != nil {
		t.Context.Errorf("Error dumping bytes for cached response: %v", err)
		return resp, nil
	}
	var expiration time.Duration = time.Hour
	if strings.HasPrefix(req.URL.Path, "/repos/") &&
		(strings.HasSuffix(req.URL.Path, "/commits") ||
			strings.HasSuffix(req.URL.Path, "/stats/contributors")) {
		expiration = 0
	}
	err = memcache.Set(
		t.Context,
		&memcache.Item{
			Key:        cacheKey,
			Value:      respBytes,
			Expiration: expiration,
		})
	if err != nil {
		t.Context.Errorf("Error setting cached response for %s (cache key %s, %d bytes to cache): %v",
			req.URL, cacheKey, len(respBytes), err)
	}
	return resp, nil
}
