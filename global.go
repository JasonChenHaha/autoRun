package main

import "runtime"

var (
	VERSION = "debug"
	aesKey = []byte("A@S#UNs%uSDMu*sa")
)

type bodyInter interface{
	time() int64
	auth() string
}

type CommonBody struct {
	Auth string
	Time int64
}
func (this *CommonBody) time() int64 {
	return this.Time
}
func (this *CommonBody) auth() string {
	return this.Auth
}

type fileBody struct {
	CommonBody
	Name string
	Data string
	Root string
	Path string
}

type cmdBody struct {
	CommonBody
	Cmd string
}

func isLinux() bool {
	return runtime.GOOS == "linux"
}

func isDarwin() bool {
	return runtime.GOOS == "darwin"
}

func isWindows() bool {
	return runtime.GOOS == "windows"
}