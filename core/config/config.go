// Package config define configuração VERSIONADA do core. O schema_version
// permite migrações explícitas; nunca há defaults mágicos espalhados.
package config

import (
	"encoding/json"
	"fmt"
)

const SchemaVersion = 1

type Config struct {
	SchemaVersion int              `json:"schema_version"`
	Queue         QueueConfig      `json:"queue"`
	Bandwidth     BandwidthConfig  `json:"bandwidth"`
	Storage       StorageConfig    `json:"storage"`
	Security      SecurityConfig   `json:"security"`
	Commercial    CommercialConfig `json:"commercial"` // preços: CONFIG, não constantes no código
}

type QueueConfig struct {
	MaxConcurrentTasks int  `json:"max_concurrent_tasks"`
	AutoStart          bool `json:"auto_start"`
	RetryMaxAttempts   int  `json:"retry_max_attempts"`
}

type BandwidthConfig struct {
	GlobalLimitBps    int64 `json:"global_limit_bps"` // 0 = sem limite
	PerTaskLimitBps   int64 `json:"per_task_limit_bps"`
	BackgroundProfile bool  `json:"background_profile"` // perfil 2º plano mais restrito
}

type StorageConfig struct {
	DefaultDir        string `json:"default_dir"`
	TempSuffix        string `json:"temp_suffix"` // ex.: ".svpart" — finalização atómica por rename
	KeepTempOnFailure bool   `json:"keep_temp_on_failure"`
}

type SecurityConfig struct {
	AllowPrivateNetworks bool `json:"allow_private_networks"` // UI pede confirmação explícita p/ ativar
	BlockDangerousExec   bool `json:"block_dangerous_exec"`   // default true; nunca executar conteúdo descarregado
}

type CommercialConfig struct {
	ProductID     string `json:"product_id"`
	PriceBRLCents int    `json:"price_brl_cents"` // R$8 => 800 — configurável, NÃO hardcoded na UI
	Edition       string `json:"edition"`
}

func Default() Config {
	return Config{
		SchemaVersion: SchemaVersion,
		Queue:         QueueConfig{MaxConcurrentTasks: 3, AutoStart: true, RetryMaxAttempts: 5},
		Bandwidth:     BandwidthConfig{},
		Storage:       StorageConfig{TempSuffix: ".svpart", KeepTempOnFailure: true},
		Security:      SecurityConfig{BlockDangerousExec: true},
		Commercial:    CommercialConfig{ProductID: "streamvault-windows", PriceBRLCents: 800, Edition: "pro"},
	}
}

// Parse valida versão e rejeita configs futuras desconhecidas em vez de as
// interpretar silenciosamente mal.
func Parse(data []byte) (Config, error) {
	var probe struct {
		SchemaVersion int `json:"schema_version"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return Config{}, fmt.Errorf("config: JSON inválido: %w", err)
	}
	if probe.SchemaVersion > SchemaVersion {
		return Config{}, fmt.Errorf("config: schema_version %d é mais recente que este core (%d); atualize a aplicação", probe.SchemaVersion, SchemaVersion)
	}
	if probe.SchemaVersion < SchemaVersion {
		// ponto único de migração futura
		return Config{}, fmt.Errorf("config: schema_version %d requer migração (atual: %d)", probe.SchemaVersion, SchemaVersion)
	}
	c := Default()
	if err := json.Unmarshal(data, &c); err != nil {
		return Config{}, fmt.Errorf("config: %w", err)
	}
	return c, nil
}
