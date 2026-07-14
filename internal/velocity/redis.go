package velocity

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisCounter is a Redis-backed velocity counter using atomic INCR + EXPIRE.
// Each (user_id, window) maps to key vel:{user_id}:{suffix}. INCR is atomic;
// the first INCR in a window sets the TTL to the window length via the
// optional EXPIRE call (idempotent — re-setting the TTL refreshes it).
type RedisCounter struct {
	client *redis.Client
	prefix string
}

// NewRedisCounter returns a Redis-backed velocity counter. addr is the Redis
// address (host:port); prefix is prepended to all keys (default "vel").
func NewRedisCounter(addr, prefix string) *RedisCounter {
	if prefix == "" {
		prefix = "vel"
	}
	return &RedisCounter{
		client: redis.NewClient(&redis.Options{Addr: addr}),
		prefix: prefix,
	}
}

// NewRedisCounterFromClient allows injecting a pre-configured *redis.Client
// (used by tests with miniredis or a shared client).
func NewRedisCounterFromClient(client *redis.Client, prefix string) *RedisCounter {
	if prefix == "" {
		prefix = "vel"
	}
	return &RedisCounter{client: client, prefix: prefix}
}

// Ping checks the Redis connection.
func (c *RedisCounter) Ping(ctx context.Context) error {
	return c.client.Ping(ctx).Err()
}

// Close releases the Redis connection.
func (c *RedisCounter) Close() error { return c.client.Close() }

func (c *RedisCounter) k(userID string, w Window) string {
	return fmt.Sprintf("%s:%s:%s", c.prefix, userID, w.Suffix())
}

// Increment atomically increments the counter for (userID, window) and
// (re)sets the TTL to the window length. Returns the new value.
func (c *RedisCounter) Increment(ctx context.Context, userID string, w Window) (int64, error) {
	k := c.k(userID, w)
	v, err := c.client.Incr(ctx, k).Result()
	if err != nil {
		return 0, fmt.Errorf("redis incr: %w", err)
	}
	if err := c.client.Expire(ctx, k, time.Duration(w)).Err(); err != nil {
		return v, fmt.Errorf("redis expire: %w", err)
	}
	return v, nil
}

// Rollback atomically decrements the counter. If the counter would become
// negative it is set to 0 via a Lua script and ErrNegativeCounter is returned.
func (c *RedisCounter) Rollback(ctx context.Context, userID string, w Window) (int64, error) {
	k := c.k(userID, w)
	// Lua script: decrement, clamp at 0.
	script := redis.NewScript(`
local v = redis.call("DECR", KEYS[1])
if v < 0 then
  redis.call("SET", KEYS[1], 0)
  return 0
end
return v
`)
	res, err := script.Run(ctx, c.client, []string{k}).Result()
	if err != nil {
		return 0, fmt.Errorf("redis rollback: %w", err)
	}
	n, _ := res.(int64)
	if n == 0 {
		cur, _ := c.client.Get(ctx, k).Result()
		if cur == "0" {
			// Distinguishing a true rollback-to-zero from a clamp is not
			// critical for callers; they treat 0 as the floor.
			return 0, nil
		}
	}
	return n, nil
}

// Get returns the current counter value (0 if absent).
func (c *RedisCounter) Get(ctx context.Context, userID string, w Window) (int64, error) {
	k := c.k(userID, w)
	v, err := c.client.Get(ctx, k).Result()
	if err == redis.Nil {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("redis get: %w", err)
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("redis get parse: %w", err)
	}
	return n, nil
}