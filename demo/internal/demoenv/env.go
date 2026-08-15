// Package demoenv loads the shared local demo environment file.
package demoenv

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Load reads the shared demo/.env if it exists. Existing process environment
// variables take precedence, so CI or an explicit shell export can override
// local demo values. The parser intentionally supports only simple KEY=VALUE
// lines; secrets are never printed.
func Load() error {
	candidates := []string{}
	if explicit := strings.TrimSpace(os.Getenv("DEMO_ENV_FILE")); explicit != "" {
		candidates = append(candidates, explicit)
	}
	candidates = append(candidates, "demo/.env", "../../.env")

	for _, candidate := range candidates {
		path := filepath.Clean(candidate)
		if err := loadFile(path); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return err
		}
		return nil
	}
	return nil
}

func loadFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(key) == "" {
			return fmt.Errorf("invalid environment line %d in %s", lineNumber, path)
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if len(value) >= 2 && ((value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'')) {
			value = value[1 : len(value)-1]
		}
		if _, exists := os.LookupEnv(key); !exists {
			if err := os.Setenv(key, value); err != nil {
				return fmt.Errorf("set %s from %s: %w", key, path, err)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	return nil
}
