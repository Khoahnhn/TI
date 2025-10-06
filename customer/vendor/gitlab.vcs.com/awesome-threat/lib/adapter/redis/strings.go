package redis

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	rd "github.com/go-redis/redis/v8"

	"gitlab.viettelcyber.com/awesome-threat/library/clock"
)

type redisStrings struct {
	con   *rd.Client
	mutex *sync.Mutex
}

func NewStrings(con *rd.Client, mutex *sync.Mutex) Strings {
	// Success
	return &redisStrings{
		con:   con,
		mutex: mutex,
	}
}

func (r *redisStrings) Set(key, value string, ttl clock.Duration) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	// Success
	return r.con.Set(context.Background(), key, value, time.Duration(ttl)).Err()
}

func (r *redisStrings) SetO(key string, value interface{}, ttl clock.Duration) error {
	bts, err := json.Marshal(value)
	if err != nil {
		return err
	}
	// Success
	return r.Set(key, string(bts), ttl)
}

func (r *redisStrings) Get(key string) (string, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	result, err := r.con.Get(context.Background(), key).Result()
	if err == rd.Nil {
		return result, errors.New(NotFoundError)
	}
	// Success
	return result, nil
}

func (r *redisStrings) GetO(key string, pointer interface{}) error {
	result, err := r.Get(key)
	if err != nil {
		return err
	}
	if err = json.Unmarshal([]byte(result), pointer); err != nil {
		return err
	}
	// Success
	return nil
}
