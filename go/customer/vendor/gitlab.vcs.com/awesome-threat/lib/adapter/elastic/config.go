package elastic

type (
	Config struct {
		Address string     `json:"address" yaml:"address"`
		Auth    AuthConfig `json:"auth" yaml:"auth"`
	}

	AuthConfig struct {
		Enable   bool   `json:"enable" yaml:"enable"`
		Username string `json:"username" yaml:"username"`
		Password string `json:"password" yaml:"password"`
	}
)
