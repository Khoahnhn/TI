package redis

import (
	"context"
	"encoding/json"
	"errors"
	"sync"

	rd "github.com/go-redis/redis/v8"
)

type (
	redisLists struct {
		con       *rd.Client
		mutex     *sync.Mutex
		fifoLists FIFOLists
		lifoLists LIFOLists
	}

	redisFIFOLists struct {
		lists Lists
		mutex *sync.Mutex
	}

	redisLIFOLists struct {
		lists Lists
		mutex *sync.Mutex
	}
)

func NewLists(con *rd.Client, mutex *sync.Mutex) Lists {
	instance := &redisLists{
		con:   con,
		mutex: mutex,
	}
	instance.fifoLists = NewFIFOLists(instance, mutex)
	instance.lifoLists = NewLIFOLists(instance, mutex)
	// Success
	return instance
}

func NewFIFOLists(instance Lists, mutex *sync.Mutex) FIFOLists {
	// Success
	return &redisFIFOLists{
		lists: instance,
		mutex: mutex,
	}
}

func NewLIFOLists(instance Lists, mutex *sync.Mutex) FIFOLists {
	// Success
	return &redisLIFOLists{
		lists: instance,
		mutex: mutex,
	}
}

func (r *redisLists) FIFO() FIFOLists {
	// Success
	return r.fifoLists
}

func (r *redisLists) LIFO() LIFOLists {
	// Success
	return r.lifoLists
}

func (r *redisLists) Len(key string) (int64, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	count, err := r.con.LLen(context.Background(), key).Result()
	if err != nil {
		return 0, err
	}
	// Success
	return count, nil
}

func (r *redisLists) LPush(key, value string) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	// Success
	return r.con.LPush(context.Background(), key, value).Err()
}

func (r *redisLists) LPushO(key string, value interface{}) error {
	bts, err := json.Marshal(value)
	if err != nil {
		return err
	}
	// Success
	return r.LPush(key, string(bts))
}

func (r *redisLists) RPush(key, value string) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	// Success
	return r.con.RPush(context.Background(), key, value).Err()
}

func (r *redisLists) RPushO(key string, value interface{}) error {
	bts, err := json.Marshal(value)
	if err != nil {
		return err
	}
	// Success
	return r.RPush(key, string(bts))
}

func (r *redisLists) LPop(key string) (string, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	result, err := r.con.LPop(context.Background(), key).Result()
	if err == rd.Nil {
		return result, errors.New(NotFoundError)
	}
	// Success
	return result, nil
}

func (r *redisLists) LPopO(key string, pointer interface{}) error {
	result, err := r.LPop(key)
	if err != nil {
		return err
	}
	if err = json.Unmarshal([]byte(result), pointer); err != nil {
		return err
	}
	// Success
	return nil
}

func (r *redisLists) RPop(key string) (string, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	result, err := r.con.RPop(context.Background(), key).Result()
	if err == rd.Nil {
		return result, errors.New(NotFoundError)
	}
	// Success
	return result, nil
}

func (r *redisLists) RPopO(key string, pointer interface{}) error {
	result, err := r.RPop(key)
	if err != nil {
		return err
	}
	if err = json.Unmarshal([]byte(result), pointer); err != nil {
		return err
	}
	// Success
	return nil
}

func (r *redisFIFOLists) Push(key, value string) error {
	// Success
	return r.lists.LPush(key, value)
}

func (r *redisFIFOLists) PushO(key string, value interface{}) error {
	// Success
	return r.lists.LPushO(key, value)
}

func (r *redisFIFOLists) Pop(key string) (string, error) {
	// Success
	return r.lists.LPop(key)
}

func (r *redisFIFOLists) PopO(key string, pointer interface{}) error {
	// Success
	return r.lists.LPopO(key, pointer)
}

func (r *redisLIFOLists) Push(key, value string) error {
	// Success
	return r.lists.LPush(key, value)
}

func (r *redisLIFOLists) PushO(key string, value interface{}) error {
	// Success
	return r.lists.LPushO(key, value)
}

func (r *redisLIFOLists) Pop(key string) (string, error) {
	// Success
	return r.lists.RPop(key)
}

func (r *redisLIFOLists) PopO(key string, pointer interface{}) error {
	// Success
	return r.lists.RPopO(key, pointer)
}
