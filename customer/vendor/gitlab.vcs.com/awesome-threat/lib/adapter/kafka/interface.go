package kafka

type (
	Consumer interface {
		Close()
	}

	Producer interface {
		Produce(topic string, key interface{}, value interface{}) error
		ProduceObject(topic string, key interface{}, value interface{}, compact bool) error
		Close()
	}
)
