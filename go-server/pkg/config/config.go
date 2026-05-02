package config

import (
	"strings"

	"github.com/spf13/viper"
)

type Config struct {
	Environment      string `mapstructure:"ENVIRONMENT"`
	GRPCPort         string `mapstructure:"GRPC_PORT"`
	DBDSN            string `mapstructure:"DB_DSN"`
	SonarQubeBaseURL string `mapstructure:"SONARQUBE_BASE_URL"`
	SonarQubeToken   string `mapstructure:"SONARQUBE_TOKEN"`
	SonarScannerBin  string `mapstructure:"SONAR_SCANNER_BIN"`
	RedisAddr        string `mapstructure:"REDIS_ADDR"`
	LogLevel         string `mapstructure:"LOG_LEVEL"`
}

func Load() (Config, error) {
	v := viper.New()
	v.SetConfigName(".env")
	v.SetConfigType("env")
	v.AddConfigPath(".")
	v.AddConfigPath("..")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	v.SetDefault("ENVIRONMENT", "development")
	v.SetDefault("GRPC_PORT", "50051")
	v.SetDefault("SONAR_SCANNER_BIN", "sonar-scanner")
	v.SetDefault("REDIS_ADDR", "localhost:6379")
	v.SetDefault("LOG_LEVEL", "info")

	_ = v.ReadInConfig()
	_ = v.BindEnv("DB_DSN", "DB_DSN", "DATABASE_URL")
	_ = v.BindEnv("SONARQUBE_BASE_URL", "SONARQUBE_BASE_URL", "SONARQUBE_HOST")
	_ = v.BindEnv("SONARQUBE_TOKEN", "SONARQUBE_TOKEN", "SONAR_TOKEN")

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return Config{}, err
	}
	if strings.TrimSpace(cfg.GRPCPort) == "" {
		cfg.GRPCPort = "50051"
	}
	if strings.TrimSpace(cfg.SonarScannerBin) == "" {
		cfg.SonarScannerBin = "sonar-scanner"
	}
	if strings.TrimSpace(cfg.RedisAddr) == "" {
		cfg.RedisAddr = "localhost:6379"
	}
	if strings.TrimSpace(cfg.LogLevel) == "" {
		cfg.LogLevel = "info"
	}
	return cfg, nil
}