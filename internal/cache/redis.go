package cache

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

type RedisCache struct {
	client *redis.Client
}

func NewRedisCache(addr, password string, db int) *RedisCache {
	return &RedisCache{
		client: redis.NewClient(&redis.Options{
			Addr:     addr,
			Password: password,
			DB:       db,
		}),
	}
}

func (c *RedisCache) Get(ctx context.Context, key string) ([]byte, error) {
	val, err := c.client.Get(ctx, cacheKey(key)).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return val, nil
}

func (c *RedisCache) Set(ctx context.Context, key string, data []byte, ttl time.Duration) error {
	return c.client.Set(ctx, cacheKey(key), data, ttl).Err()
}

// Client returns the underlying Redis client. This allows other components
// (e.g. the rate limiter) to share the connection without creating a second one.
func (c *RedisCache) Client() *redis.Client {
	return c.client
}

// Ping verifies the Redis connection is alive.
func (c *RedisCache) Ping(ctx context.Context) error {
	return c.client.Ping(ctx).Err()
}

// Close closes the underlying Redis client.
func (c *RedisCache) Close() error {
	return c.client.Close()
}

func cacheKey(name string) string {
	return fmt.Sprintf("intel:%s", name)
}
