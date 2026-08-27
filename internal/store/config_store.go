package store

import (
	"database/sql"
	"encoding/json"

	"task270-sbomreach/internal/model"
)

// ConfigStore 提供部署配置的 SQLite 持久化。
type ConfigStore struct {
	db *sql.DB
}

// NewConfigStore 构造配置仓库。
func NewConfigStore(db *sql.DB) *ConfigStore {
	return &ConfigStore{db: db}
}

// Save 整体保存一份部署配置：在单个事务内删除旧配置并写入新配置。
// 任意步骤失败都回滚，保留原有入口符号与条件键，绝不清空成空配置。
func (s *ConfigStore) Save(cfg *model.DeployConfig) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	// 失败一律回滚；只有走到末尾 Commit 成功才落库。
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`DELETE FROM deploy_configs WHERE release_id = ?`, cfg.ReleaseID); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM entry_symbols WHERE release_id = ?`, cfg.ReleaseID); err != nil {
		return err
	}
	updated := cfg.UpdatedAt
	for key, val := range cfg.Conditions {
		raw, err := json.Marshal(val.Raw)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`
			INSERT INTO deploy_configs(release_id, cfg_key, cfg_value, updated_at)
			VALUES(?, ?, ?, ?)`,
			cfg.ReleaseID, key, string(raw), formatTime(updated)); err != nil {
			return err
		}
	}
	for _, sym := range cfg.EntrySymbols {
		if _, err := tx.Exec(`
			INSERT INTO entry_symbols(release_id, symbol) VALUES(?, ?)`,
			cfg.ReleaseID, sym); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Load 读取某发布物的部署配置。
func (s *ConfigStore) Load(releaseID string) (*model.DeployConfig, error) {
	cfg := model.NewDeployConfig(releaseID)

	rows, err := s.db.Query(`
		SELECT cfg_key, cfg_value FROM deploy_configs WHERE release_id = ?`, releaseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var key, raw string
		if err := rows.Scan(&key, &raw); err != nil {
			return nil, err
		}
		var value any
		if err := json.Unmarshal([]byte(raw), &value); err != nil {
			return nil, err
		}
		cfg.Conditions[key] = model.ConfigValue{Raw: value}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	syms, err := s.db.Query(`SELECT symbol FROM entry_symbols WHERE release_id = ? ORDER BY symbol`, releaseID)
	if err != nil {
		return nil, err
	}
	defer syms.Close()
	for syms.Next() {
		var sym string
		if err := syms.Scan(&sym); err != nil {
			return nil, err
		}
		cfg.EntrySymbols = append(cfg.EntrySymbols, sym)
	}
	if err := syms.Err(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// HasAny 判断某发布物是否已保存过部署配置。
func (s *ConfigStore) HasAny(releaseID string) (bool, error) {
	var n int
	err := s.db.QueryRow(`
		SELECT COUNT(*) FROM deploy_configs WHERE release_id = ?`, releaseID).Scan(&n)
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

var _ = sql.ErrNoRows
