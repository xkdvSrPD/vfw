// Package config persists vfw rules and state under /etc/vfw by default.
package config

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"vfw/internal/model"
)

const (
	rulesFileName = "rules.json"
	stateFileName = "state.json"
)

// Store manages the config directory used by vfw.
type Store struct {
	configDir string
}

// NewStore constructs a persistent store rooted at configDir.
func NewStore(configDir string) *Store {
	return &Store{configDir: configDir}
}

// LoadRules reads every persisted rule in stable order.
func (s *Store) LoadRules(ctx context.Context) ([]model.Rule, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	path := filepath.Join(s.configDir, rulesFileName)
	buffer, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read rules: %w", err)
	}
	var rules []model.Rule
	if err := json.Unmarshal(buffer, &rules); err != nil {
		return nil, fmt.Errorf("decode rules: %w", err)
	}
	for index := range rules {
		if err := rules[index].EnsureDefaults(); err != nil {
			return nil, fmt.Errorf("normalize rule %d: %w", index+1, err)
		}
	}
	return rules, nil
}

// SaveRules writes the complete rule list atomically.
func (s *Store) SaveRules(ctx context.Context, rules []model.Rule) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.MkdirAll(s.configDir, 0o755); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	clone := make([]model.Rule, len(rules))
	copy(clone, rules)
	for index := range clone {
		if err := clone[index].EnsureDefaults(); err != nil {
			return fmt.Errorf("normalize rule %d: %w", index+1, err)
		}
	}
	buffer, err := json.MarshalIndent(clone, "", "  ")
	if err != nil {
		return fmt.Errorf("encode rules: %w", err)
	}
	return writeFileAtomically(filepath.Join(s.configDir, rulesFileName), buffer, 0o644)
}

// LoadState reads the mutable firewall runtime state.
func (s *Store) LoadState(ctx context.Context) (model.State, error) {
	if err := ctx.Err(); err != nil {
		return model.State{}, err
	}
	path := filepath.Join(s.configDir, stateFileName)
	buffer, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return model.State{}, nil
	}
	if err != nil {
		return model.State{}, fmt.Errorf("read state: %w", err)
	}
	var state model.State
	if err := json.Unmarshal(buffer, &state); err != nil {
		return model.State{}, fmt.Errorf("decode state: %w", err)
	}
	return state, nil
}

// SaveState writes the runtime state atomically.
func (s *Store) SaveState(ctx context.Context, state model.State) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.MkdirAll(s.configDir, 0o755); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	buffer, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("encode state: %w", err)
	}
	return writeFileAtomically(filepath.Join(s.configDir, stateFileName), buffer, 0o644)
}

func writeFileAtomically(path string, buffer []byte, mode os.FileMode) error {
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, buffer, mode); err != nil {
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename temp file: %w", err)
	}
	return nil
}
