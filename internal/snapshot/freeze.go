package snapshot

import (
	"fmt"

	"task270-sbomreach/internal/model"
)

// FreezeRelease 执行发布物封存的冻结校验：
//   - 必须已有至少一份已发布快照，否则拒绝封存（证明缺失）；
//   - 封存后快照保持只读，不再允许创建新草稿。
func FreezeRelease(release *model.Release, publishedSnapshots int) (int, error) {
	if publishedSnapshots < 1 {
		return publishedSnapshots, fmt.Errorf(
			"%w: 发布物 %s 尚无已发布证明快照，拒绝封存",
			model.ErrStateTransition, release.Name)
	}
	if err := release.Seal(); err != nil {
		return publishedSnapshots, err
	}
	return publishedSnapshots, nil
}
