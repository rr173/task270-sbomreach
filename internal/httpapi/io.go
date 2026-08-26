package httpapi

import (
	"io"
	"net/http"
)

// ioReadAllLimited 读取请求体（上限 4MB）。
func ioReadAllLimited(r *http.Request) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r.Body, 4<<20))
}
