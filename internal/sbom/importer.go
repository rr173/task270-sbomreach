package sbom

import (
	"fmt"

	"task270-sbomreach/internal/model"
	"task270-sbomreach/internal/store"
)

// ImportResult 是一次 SBOM 导入的结果摘要。
type ImportResult struct {
	Imported int `json:"imported"`
	Updated  int `json:"updated"`
	Total    int `json:"total"`
}

// Importer 把解析后的 SBOM 构件批量写入仓库（幂等 upsert）。
type Importer struct {
	components *store.ComponentStore
	imports    *store.SBOMImportStore
}

// NewImporter 构造导入器。
func NewImporter(components *store.ComponentStore, imports *store.SBOMImportStore) *Importer {
	return &Importer{components: components, imports: imports}
}

// Import 导入 SBOM 文档到指定发布物。
// 构件按 PURL 幂等：已存在则更新版本/依赖，不存在则新建。
func (im *Importer) Import(releaseID string, doc *SBOMDoc) (*ImportResult, error) {
	result := &ImportResult{Total: len(doc.Nodes())}
	for _, node := range doc.Nodes() {
		if err := model.ValidateComponent(node.PURL, node.Name, node.Version); err != nil {
			return nil, fmt.Errorf("构件 %s: %w", node.PURL, err)
		}
		c := model.NewComponent(releaseID, node.PURL, node.Name, node.Version,
			node.Type, node.DependsOn)
		added, err := im.components.Upsert(c)
		if err != nil {
			return nil, fmt.Errorf("写入构件 %s: %w", node.PURL, err)
		}
		if added {
			result.Imported++
		} else {
			result.Updated++
		}
	}
	if err := im.imports.Record(releaseID, doc.Format, doc.Source); err != nil {
		return nil, fmt.Errorf("记录导入批次: %w", err)
	}
	return result, nil
}
