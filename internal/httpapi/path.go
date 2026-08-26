package httpapi

import "strings"

// splitPath 把路径按 / 切分并去掉空段（返回例如 ["api","releases","rel-1","vulns"]）。
func splitPath(path string) []string {
	raw := strings.Split(path, "/")
	out := []string{}
	for _, p := range raw {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
