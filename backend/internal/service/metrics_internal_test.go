package service

import (
	"strconv"
	"testing"
	"time"
)

func TestTTLCacheExpiresAndStaysBounded(t *testing.T) {
	var c ttlCache
	t0 := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	c.put("a", Metrics{Days: 30}, t0)
	if m, ok := c.get("a", t0.Add(metricsTTL-time.Second)); !ok || m.Days != 30 {
		t.Fatal("fresh entry missing")
	}
	if _, ok := c.get("a", t0.Add(metricsTTL)); ok {
		t.Fatal("expired entry served")
	}
	// Full of expired entries: they are evicted.
	c = ttlCache{}
	for i := range metricsCacheLimit {
		c.put(strconv.Itoa(i), Metrics{}, t0)
	}
	c.put("fresh", Metrics{}, t0.Add(metricsTTL))
	if len(c.m) != 1 {
		t.Fatal(len(c.m))
	}
	// Full of live entries: the cache starts over rather than growing.
	for i := range metricsCacheLimit + 10 {
		c.put(strconv.Itoa(i), Metrics{}, t0.Add(metricsTTL))
	}
	if len(c.m) > metricsCacheLimit {
		t.Fatal(len(c.m))
	}
}
