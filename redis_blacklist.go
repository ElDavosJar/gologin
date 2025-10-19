package gologin

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisTokenBlacklist implements TokenBlacklist using Redis for distributed revocation
// Usage:
//   blacklist := NewRedisTokenBlacklist(redisClient)
//   blacklist.Add(tokenID, expiresAt)
type RedisTokenBlacklist struct {
	client *redis.Client
}

func NewRedisTokenBlacklist(client *redis.Client) *RedisTokenBlacklist {
	return &RedisTokenBlacklist{client: client}
}

func (r *RedisTokenBlacklist) Add(tokenID string, expiresAt time.Time) error {
	ctx := context.Background()
	if tokenID == "" {
		return fmt.Errorf("tokenID cannot be empty")
	}
	ttl := time.Until(expiresAt)
	return r.client.Set(ctx, "blacklist:"+tokenID, "1", ttl).Err()
}

func (r *RedisTokenBlacklist) IsBlacklisted(tokenID string) bool {
	ctx := context.Background()
	result, err := r.client.Exists(ctx, "blacklist:"+tokenID).Result()
	if err != nil {
		// Si Redis falla, por seguridad deniega el acceso
		return true
	}
	return result > 0
}

func (r *RedisTokenBlacklist) Remove(tokenID string) error {
	ctx := context.Background()
	return r.client.Del(ctx, "blacklist:"+tokenID).Err()
}
