package redis

import (
	"time"

	"gitlab.viettelcyber.com/awesome-threat/library/clock"
)

type (
	Service interface {
		Connection() Connection
		Keys() Keys
		Strings() Strings
		Lists() Lists
	}

	Connection interface {
		Ping() error
	}

	Keys interface {
		All() ([]string, error)
		Delete(key ...string) error
		Expire(key string, ttl clock.Duration) error
		ExpireAt(key string, tm time.Time) error
	}

	Strings interface {
		Set(key, value string, ttl clock.Duration) error
		SetO(key string, value interface{}, ttl clock.Duration) error
		Get(key string) (string, error)
		GetO(key string, pointer interface{}) error
	}

	Lists interface {
		FIFO() FIFOLists
		LIFO() LIFOLists
		Len(key string) (int64, error)
		LPush(key, value string) error
		LPushO(key string, value interface{}) error
		RPush(key, value string) error
		RPushO(key string, value interface{}) error
		LPop(key string) (string, error)
		LPopO(key string, pointer interface{}) error
		RPop(key string) (string, error)
		RPopO(key string, pointer interface{}) error
	}

	FIFOLists interface {
		Push(key, value string) error
		PushO(key string, value interface{}) error
		Pop(key string) (string, error)
		PopO(key string, pointer interface{}) error
	}

	LIFOLists interface {
		Push(key, value string) error
		PushO(key string, value interface{}) error
		Pop(key string) (string, error)
		PopO(key string, pointer interface{}) error
	}
)
