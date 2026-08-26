// Package sbom 负责解析 SBOM（软件物料清单）并批量导入构件。
package sbom

import (
	"encoding/json"
	"fmt"

	"task270-sbomreach/internal/model"
)

// SBOMFormat 支持导入的 SBOM 格式。
const (
	FormatCycloneDX = "cyclonedx"
	FormatSPDX      = "spdx"
	FormatMinimal   = "minimal"
)

// ComponentNode 是 SBOM 内单个构件的声明。
type ComponentNode struct {
	PURL      string   `json:"purl"`
	Name      string   `json:"name"`
	Version   string   `json:"version"`
	Type      string   `json:"type,omitempty"`
	DependsOn []string `json:"depends_on,omitempty"`
}

// SBOMDoc 是本服务统一的 SBOM 中间表示。
// 兼容 CycloneDX 风格（components 数组）与 SPDX 风格（packages 数组）字段，
// 也接受 minimal（components 数组 + 顶层 metadata.name/version）。
type SBOMDoc struct {
	Format     string          `json:"format"`
	Source     string          `json:"source,omitempty"`
	Metadata   SBOMMetadata    `json:"metadata,omitempty"`
	Components []ComponentNode `json:"components"`
	Packages   []ComponentNode `json:"packages"`
}

// SBOMMetadata 是 SBOM 的文档级元数据。
type SBOMMetadata struct {
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
	Tool    string `json:"tool,omitempty"`
}

// Parse 将 JSON 字节解析为 SBOMDoc 并做格式归一化。
// 输入格式可以是 cyclonedx / spdx / minimal 三选一（由 format 字段声明）。
func Parse(data []byte, format, source string) (*SBOMDoc, error) {
	var doc SBOMDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("解析 SBOM JSON: %w", err)
	}
	switch format {
	case FormatCycloneDX, FormatSPDX, FormatMinimal:
		doc.Format = format
	default:
		return nil, fmt.Errorf("%w: 不支持的 SBOM 格式 %q",
			model.ErrInvalidArgument, format)
	}
	doc.Source = source
	if err := doc.normalize(); err != nil {
		return nil, err
	}
	return &doc, nil
}

// normalize 合并 components/packages 并去重、校验。
func (d *SBOMDoc) normalize() error {
	seen := map[string]bool{}
	merged := make([]ComponentNode, 0, len(d.Components)+len(d.Packages))
	for _, list := range [][]ComponentNode{d.Components, d.Packages} {
		for _, c := range list {
			if c.PURL == "" {
				return fmt.Errorf("%w: SBOM 内存在缺少 purl 的构件（%s@%s）",
					model.ErrInvalidArgument, c.Name, c.Version)
			}
			if seen[c.PURL] {
				continue
			}
			seen[c.PURL] = true
			if c.Type == "" {
				c.Type = "library"
			}
			if c.DependsOn == nil {
				c.DependsOn = []string{}
			}
			merged = append(merged, c)
		}
	}
	d.Components = merged
	d.Packages = nil
	return nil
}

// Nodes 返回归一化后的构件节点列表。
func (d *SBOMDoc) Nodes() []ComponentNode {
	return d.Components
}
