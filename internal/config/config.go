package config

import (
	"flag"
	"github.com/ilyakaznacheev/cleanenv"
	"os"
)

type Config struct {
	Env      string `yaml:"env" env-default:"local" env-description:"Environment" env-choices:"local,dev,prod"`
	ApiPort  int    `yaml:"api_port" env-default:"8080"`
	ApiHost  string `yaml:"api_host" env-default:"localhost"`
	Postgres `yaml:"postgres"`
}

type Postgres struct {
	Host string `yaml:"host" env-default:"localhost"`
	Port string `yaml:"port" env-default:"5433"`
	User string `yaml:"user" env-default:"test"`
	Pass string `yaml:"pass" env-default:"12345"`
	Db   string `yaml:"db" env-default:"test_db"`
}

func MustLoad() *Config {
	path := fetchConfigPath()

	if _, err := os.Stat(path); os.IsNotExist(err) {
		panic("config file does not exist: " + path)
	}

	var cfg Config

	if err := cleanenv.ReadConfig(path, &cfg); err != nil {
		panic("Failed to read config" + err.Error())
	}

	return &cfg
}

func fetchConfigPath() string {
	var res string

	flag.StringVar(&res, "config", "", "path to config file")
	flag.Parse()

	if res == "" {
		res = os.Getenv("CONFIG_PATH")
	}

	return res
}
