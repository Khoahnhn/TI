package redis

import (
	"context"
	"sync"
	"time"

	rd "github.com/go-redis/redis/v8"

	"gitlab.viettelcyber.com/awesome-threat/library/clock"
)

type redisKeys struct {
	con   *rd.Client
	mutex *sync.Mutex
}

func NewKeys(con *rd.Client, mutex *sync.Mutex) Keys {
	// Success
	return &redisKeys{
		con:   con,
		mutex: mutex,
	}
}

func (r *redisKeys) All() ([]string, error) {
	// Success
	return r.con.Keys(context.Background(), "*").Result()
}

func (r *redisKeys) Delete(keys ...string) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	// Success
	return r.con.Del(context.Background(), keys...).Err()
}

func (r *redisKeys) Expire(key string, ttl clock.Duration) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	// Success
	return r.con.Expire(context.Background(), key, time.Duration(ttl)).Err()
}

func (r *redisKeys) ExpireAt(key string, tm time.Time) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	// Success
	return r.con.ExpireAt(context.Background(), key, tm).Err()
}
