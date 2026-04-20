package engine

import (
	"context"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type RateLimiter struct {
	mu       sync.RWMutex
	limiters map[string]*rate.Limiter
	rps      int
	delay    time.Duration
}

func NewRateLimiter(rps int, delay time.Duration) *RateLimiter {
	return &RateLimiter{
		limiters: make(map[string]*rate.Limiter),
		rps:      rps,
		delay:    delay,
	}
}

func (r *RateLimiter) limiter(host string) *rate.Limiter {
	r.mu.RLock()
	l, ok := r.limiters[host]
	r.mu.RUnlock()
	if ok {
		return l
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	l = rate.NewLimiter(rate.Limit(r.rps), r.rps)
	r.limiters[host] = l
	return l
}

func (r *RateLimiter) Wait(ctx context.Context, host string) error {
	if err := r.limiter(host).Wait(ctx); err != nil {
		return err
	}
	if r.delay > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(r.delay):
		}
	}
	return nil
}
