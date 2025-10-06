package redis

import (
	"crypto/tls"
	"os"
	"sync"

	rd "github.com/go-redis/redis/v8"

	"gitlab.viettelcyber.com/awesome-threat/library/clock"
	"gitlab.viettelcyber.com/awesome-threat/library/log/pencil"
)

type redisConnector struct {
	logger      pencil.Logger
	rConnection Connection
	rKeys       Keys
	rLists      Lists
	rStrings    Strings
	con         *rd.Client
	mutex       *sync.Mutex
	config      Config
}

func NewService(conf Config, tlsConf *tls.Config) Service {
	logger, _ := pencil.New(Module, pencil.DebugLevel, true, os.Stdout)
	con := rd.NewClient(&rd.Options{
		Addr:      conf.Address,
		Password:  conf.Password,
		DB:        conf.Db,
		TLSConfig: tlsConf,
	})
	mutex := &sync.Mutex{}
	r := &redisConnector{
		logger:      logger,
		rConnection: NewConnection(con, mutex),
		rKeys:       NewKeys(con, mutex),
		rStrings:    NewStrings(con, mutex),
		rLists:      NewLists(con, mutex),
		con:         con,
		mutex:       mutex,
		config:      conf,
	}
	// Monitor
	r.monitor()
	// Success
	return r
}

func (r *redisConnector) Connection() Connection {
	// Success
	return r.rConnection
}

func (r *redisConnector) Keys() Keys {
	// Success
	return r.rKeys
}

func (r *redisConnector) Strings() Strings {
	// Success
	return r.rStrings
}

func (r *redisConnector) Lists() Lists {
	// Success
	return r.rLists
}

func (r *redisConnector) monitor() {
	// Reconnect connection
	go func() {
		for {
			if r.con != nil {
				if r.Connection().Ping() != nil {
					r.logger.Info("connection closed")
					r.mutex.Lock()
					for {
						r.con = rd.NewClient(&rd.Options{
							Addr:      r.config.Address,
							Password:  r.config.Password,
							DB:        r.config.Db,
							TLSConfig: nil,
						})
						if r.Connection().Ping() == nil {
							r.logger.Info("reconnect success!")
							break
						}
						r.logger.Info("reconnecting ...")
						// Sleep
						clock.Sleep(clock.Second * 3)
					}
					r.mutex.Unlock()
				}
			}
			// Sleep
			clock.Sleep(clock.Second * 10)
		}
	}()
}
