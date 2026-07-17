//go:build tinygo.wasm || libinjection_cgo

package cinjection

/*
int libinjection_sqli(void* s, int len, void* fp);
int libinjection_xss(void* s, int len);
*/
import "C"

import "unsafe"

func IsSQLi(sPtr unsafe.Pointer, sLen int, fpPtr unsafe.Pointer) bool {
	return C.libinjection_sqli(sPtr, C.int(sLen), fpPtr) == 1
}

func IsXSS(sPtr unsafe.Pointer, sLen int) bool {
	return C.libinjection_xss(sPtr, C.int(sLen)) == 1
}
