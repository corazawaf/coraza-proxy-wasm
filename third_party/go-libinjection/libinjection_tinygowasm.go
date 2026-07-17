//go:build tinygo.wasm || libinjection_cgo

package libinjection

import (
	"bytes"
	"reflect"
	"runtime"
	"unsafe"

	"github.com/wasilibs/go-libinjection/internal/cinjection"
)

func IsSQLi(input string) (bool, string) {
	if len(input) == 0 {
		return false, ""
	}

	inputSh := (*reflect.StringHeader)(unsafe.Pointer(&input))

	fp := [9]byte{}

	res := cinjection.IsSQLi(unsafe.Pointer(inputSh.Data), int(inputSh.Len), unsafe.Pointer(&fp[0]))
	runtime.KeepAlive(input)

	nullIdx := bytes.IndexByte(fp[:], 0)
	if nullIdx == -1 {
		nullIdx = 9
	}

	return res, string(fp[:nullIdx])
}

func IsXSS(input string) bool {
	if len(input) == 0 {
		return false
	}

	inputSh := (*reflect.StringHeader)(unsafe.Pointer(&input))

	res := cinjection.IsXSS(unsafe.Pointer(inputSh.Data), int(inputSh.Len))

	runtime.KeepAlive(input)
	return res
}
