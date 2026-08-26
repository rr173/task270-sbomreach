package httpapi

import "strconv"

// parseInt 解析整数查询参数。
func parseInt(s string) (int, bool) {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, false
	}
	return n, true
}

// parseBool 解析布尔查询参数。
func parseBool(s string) (bool, bool) {
	b, err := strconv.ParseBool(s)
	if err != nil {
		return false, false
	}
	return b, true
}
