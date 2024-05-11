package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"google.golang.org/appengine/v2/memcache"
	"google.golang.org/appengine/v2/log"
)

// Simple http.RoundTripper implementation which wraps an existing transport and
// caches all responses for GET and HEAD requests. Meant to speed up the
// iteration cycle during development.
type CachingTransport struct {
	Transport http.RoundTripper
	Context   context.Context
}

func (t *CachingTransport) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	if req.Method != "GET" && req.Method != "HEAD" {
		return t.Transport.RoundTrip(req)
	}
	// The Go App Engine runtime has a 250 byte limit for memcache keys, so we
	// need to hash the URL to make sure we stay under it.
	cacheHash := md5.New()
	io.WriteString(cacheHash, req.URL.String())

	authorizationHeaders, ok := req.Header["Authorization"]
	if ok {
		for i := range authorizationHeaders {
			io.WriteString(cacheHash, authorizationHeaders[i])
		}
	} else {
		io.WriteString(cacheHash, "Unauthorized")
	}
	acceptHeaders, ok := req.Header["Accept"]
	if ok {
		for i := range acceptHeaders {
			io.WriteString(cacheHash, acceptHeaders[i])
		}
	}
	cacheKey := fmt.Sprintf("CachingTransport:%x", cacheHash.Sum(nil))

	cachedRespItem, err := memcache.Get(t.Context, cacheKey)
	if err != nil && err != memcache.ErrCacheMiss {
		log.Errorf(t.Context, "Error getting cached response: %v", err)
		return t.Transport.RoundTrip(req)
	}
	if err == nil {
		cacheRespBuffer := bytes.NewBuffer(cachedRespItem.Value)
		resp, err := http.ReadResponse(bufio.NewReader(cacheRespBuffer), req)
		if err == nil {
			return resp, nil
		} else {
			log.Errorf(t.Context, "Error readings bytes for cached response: %v", err)
		}
	}
	log.Infof(t.Context, "Fetching %s", req.URL)
	resp, err = t.Transport.RoundTrip(req)
	if err != nil || resp.StatusCode != 200 {
		return
	}
	respBytes, err := httputil.DumpResponse(resp, true)
	if err != nil {
		log.Errorf(t.Context, "Error dumping bytes for cached response: %v", err)
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
		log.Errorf(t.Context, "Error setting cached response for %s (cache key %s, %d bytes to cache): %v",
			req.URL, cacheKey, len(respBytes), err)
	}
	return resp, nil
}
