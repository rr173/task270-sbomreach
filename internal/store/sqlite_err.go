package store

import (
	"errors"
	"strings"

	"task270-sbomreach/internal/model"
)

// mapSQLiteError 将 SQLite 驱动错误映射为领域错误。
// UNIQUE 约束冲突映射为 model.ErrConflict（幂等语义由调用方决定）。
func mapSQLiteError(err error) error {
	if err == nil {
		return nil
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "unique constraint") ||
		strings.Contains(msg, "constraint failed") {
		return errors.Join(model.ErrConflict, err)
	}
	if strings.Contains(msg, "foreign key") {
		return errors.Join(model.ErrNotFound, err)
	}
	return err
}
