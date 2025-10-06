package redis

import (
	"context"
	"sync"

	rd "github.com/go-redis/redis/v8"
)

type redisConnection struct {
	con   *rd.Client
	mutex *sync.Mutex
}

func NewConnection(con *rd.Client, mutex *sync.Mutex) Connection {
	// Success
	return &redisConnection{
		con:   con,
		mutex: mutex,
	}
}

func (r *redisConnection) Ping() error {
	// Success
	return r.con.Ping(context.Background()).Err()
}
