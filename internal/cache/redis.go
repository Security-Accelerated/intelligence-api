package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/securityaccelerateddevelopment/intelligence-api/internal/domain"
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

func (c *RedisCache) Get(ctx context.Context, key string) (*domain.DomainResponse, error) {
	val, err := c.client.Get(ctx, cacheKey(key)).Result()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var resp domain.DomainResponse
	if err := json.Unmarshal([]byte(val), &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *RedisCache) Set(ctx context.Context, key string, resp *domain.DomainResponse, ttl time.Duration) {
	data, err := json.Marshal(resp)
	if err != nil {
		return
	}
	c.client.Set(ctx, cacheKey(key), data, ttl)
}

func cacheKey(name string) string {
	return fmt.Sprintf("domain:%s", name)
}
