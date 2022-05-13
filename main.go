package main

func main() {
	if isLinux() {
		server()
	} else {
		client()
	}
}