package gologin

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisRateLimiter implements RateLimiter using Redis for distributed environments
// It is production-ready and works across multiple instances
//
// Usage:
//   limiter := NewRedisRateLimiter(redisClient, 5, 15*time.Minute)
//   allowed := limiter.Allow("login:username")
type RedisRateLimiter struct {
	client      *redis.Client
	maxAttempts int
	window      time.Duration
}

func NewRedisRateLimiter(client *redis.Client, maxAttempts int, window time.Duration) *RedisRateLimiter {
	return &RedisRateLimiter{
		client:      client,
		maxAttempts: maxAttempts,
		window:      window,
	}
}

func (r *RedisRateLimiter) Allow(identifier string) bool {
	ctx := context.Background()
	key := fmt.Sprintf("ratelimit:%s", identifier)
	count, err := r.client.Incr(ctx, key).Result()
	if err != nil {
		// Si Redis falla, por seguridad deniega el acceso
		return false
	}
	if count == 1 {
		r.client.Expire(ctx, key, r.window)
	}
	return count <= int64(r.maxAttempts)
}

func (r *RedisRateLimiter) Reset(identifier string) {
	ctx := context.Background()
	key := fmt.Sprintf("ratelimit:%s", identifier)
	r.client.Del(ctx, key)
}
