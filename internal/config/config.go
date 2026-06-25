package config

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	adminUserKey = "BASED_ADMIN_USERNAME"
	adminPassKey = "BASED_ADMIN_PASSWORD"
)

type Config struct {
	AdminUsername string
	AdminPassword string
}

func Load() (Config, error) {
	values := map[string]string{}
	path, err := EnvFilePath()
	if err != nil {
		return Config{}, err
	}
	if err := readEnvFile(path, values); err != nil {
		return Config{}, err
	}

	username := values[adminUserKey]
	password := values[adminPassKey]
	if v := os.Getenv(adminUserKey); v != "" {
		username = v
	}
	if v := os.Getenv(adminPassKey); v != "" {
		password = v
	}

	return Config{AdminUsername: username, AdminPassword: password}, nil
}

func WriteCredentials(username, password string) (string, error) {
	path, err := EnvFilePath()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}

	body := fmt.Sprintf("%s=%s\n%s=%s\n", adminUserKey, quoteEnv(username), adminPassKey, quoteEnv(password))
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		return "", err
	}
	return path, nil
}

func EnvFilePath() (string, error) {
	if v := os.Getenv("BASED_ENV_FILE"); v != "" {
		return v, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "based", "based.env"), nil
}

func readEnvFile(path string, values map[string]string) error {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		values[strings.TrimSpace(k)] = unquoteEnv(strings.TrimSpace(v))
	}
	return scanner.Err()
}

func quoteEnv(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	return `"` + value + `"`
}

func unquoteEnv(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
		value = value[1 : len(value)-1]
		value = strings.ReplaceAll(value, `\"`, `"`)
		value = strings.ReplaceAll(value, `\\`, `\`)
	}
	return value
}
