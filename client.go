package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type metadata struct {
	file *os.File
	md5 map[string][]interface{}
}

var confPath = "./conf/"
var confName = "autoRun.conf"
var addr string
var auth string
var dataMap = map[string]metadata{}
var template = "#addr xx.xx.xx.xx:8899 对端地址\n#auth xxx 身份码\n#send E:/go > /root/go 文件传输\n#run /root/go.sh 执行命令"

func client() {
	if len(os.Args) > 1 {
		os.Args[1] = strings.Replace(os.Args[1], "\\", "/", -1)
		index := strings.LastIndexByte(os.Args[1], '/')
		if index != -1 {
			confPath = os.Args[1][:index+1]
			confName = os.Args[1][index+1:]
		}
	}

	if _, err := os.Stat(confPath); err != nil {
		// 文件夹不存在
		if err = os.Mkdir(confPath, os.ModePerm); err != nil {
			exit("create confPath directory error: " + err.Error())
		}
	}

	if info, err := os.Stat(confPath + confName); err != nil {
		if os.IsNotExist(err) {
			// 文件不存在
			file, err := os.Create(confPath + confName)
			if err != nil {
				exit("create conf error: " + err.Error())
			}
			defer file.Close()
			file.Write([]byte(template))
			exit("error: empty conf file")
		} else {
			exit("stat conf error: " + err.Error())
		}
	} else if info.IsDir() {
		exit("error: conf is a directory")
	}else if (info.Size() == 0) {
		exit("error: empty conf file")
	}

	confFile, err := os.Open(confPath + confName)
	if err != nil {
		exit("open conf error: " + err.Error())
	}
	defer confFile.Close()
	reader := bufio.NewReader(confFile)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {if err == io.EOF {if len(line) == 0 {break}} else {exit("read conf error: " + err.Error())}}
		if line[0:1] == "#" {continue}
		// 去掉尾部换行符
		size := len(line)
		if 2 <= size && line[size-2:] == "\r\n" {
			line = line[:size-2]
		} else if 1 <= size && line[size-1:] == "\n" {
			line = line[:size-1]
		}
		// 去掉尾部空格
		for 1 <= len(line) && line[len(line)-1:] == " " {line = line[:len(line)-1]}
		if len(line) == 0 {continue}
		index := strings.IndexByte(line, ' ')
		cmd := line[:index]
		data := line[index+1:]
		switch cmd {
		case "addr":
			addr = data
			// 读md5文件
			name := "files_" + addr + ".md5"
			f, err := os.OpenFile(confPath + name, os.O_RDWR|os.O_CREATE, os.ModePerm)
			if err == nil {
				defer f.Close()
				dataMap[addr] = metadata{file:f, md5:map[string][]interface{}{}}
			} else {
				exit("open files.md5 error: " + err.Error())
			}
			reader := bufio.NewReader(f)
			for {
				line, err := reader.ReadString('\n')
				if err != nil {if err == io.EOF {if len(line) == 0 {break}} else {exit("read files.md5 error: " + err.Error())}}
				size := len(line)
				if 1 <= size && line[size-1:] == "\n" {line = line[:size-1]}
				arr := strings.Split(line, " ")
				i, err := strconv.Atoi(arr[2])
				if err != nil {exit("atoi error: " + err.Error())}
				dataMap[addr].md5[arr[0]] = []interface{}{arr[1], i}
			}
		case "auth":
			auth = data
		case "run":
			if VERSION == "release" && len(auth) == 0 {exit("error: auth required")}
			send_cmd(data)
		case "send":
			if VERSION == "release" && len(auth) == 0 {exit("error: auth required")}
			arr := strings.Split(data, " ")
			if isWindows() {
				send_file(strings.Replace(arr[0], "/", "\\", -1), arr[2])
			} else if isDarwin() {
				send_file(arr[0], arr[2])
			}
		}
	}

	// 记录文件md5
	for _, v := range dataMap {
		file := v.file
		info, err := file.Stat()
		if err != nil {exit("stat files.md5 error: " + err.Error())}
		if info.Size() > 0 { // 清空文件
			if err := file.Truncate(0); err != nil {exit("clean files.md5 error: " + err.Error())}
			if _, err := file.Seek(0, 0); err != nil {exit("seek files.md5 error: " + err.Error())}
		}
		writer := bufio.NewWriter(file)
		for name, arr := range v.md5 {
			arr[1] = arr[1].(int) - 1
			if arr[1].(int) > 0 {
				writer.WriteString(name + " " + arr[0].(string) + " " + strconv.Itoa(arr[1].(int)) + "\n")
			}
		}
		writer.Flush()
	}

	exit("")
}

func send_file(from, to string) {
	info, err := os.Stat(from)
	if err != nil {
		if os.IsNotExist(err) {
			exit("path is not exist: " + err.Error())
		} else {
			exit("stat path error: " + err.Error())
		}
	}
	if info.IsDir() {
		if isWindows() {
			if from[len(from)-1:] == "\\" {from = from[:len(from)-1]}
			//if to[len(to)-1:] == "\\" {to = to[:len(to)-1]}
		} else if isDarwin() {
			if from[len(from)-1:] == "/" {from = from[:len(from)-1]}
			//if to[len(to)-1:] == "/" {to = to[:len(to)-1]}
		}
		filepath.Walk(from, func(path string, info fs.FileInfo, err error) error {
			if err != nil {exit("walk error:" + err.Error())}
			if !info.IsDir() {
				subPath := strings.TrimPrefix(path, from)
				if isWindows() {
					subPath = strings.TrimSuffix(subPath, "\\" + info.Name())
					subPath = strings.Replace(subPath, "\\", "/", -1)
				} else if isDarwin() {
					subPath = strings.TrimSuffix(subPath, "/" + info.Name())
				}
				r, err := ioutil.ReadFile(path)
				if err != nil {exit("read file " + path + " error: " + err.Error())}
				// 文件md5校验
				h := md5.New(); h.Write(r)
				code := hex.EncodeToString(h.Sum(nil))
				key := path + "->" + to
				arr, ok := dataMap[addr].md5[key]
				if ok && arr[0].(string) == code {
					dataMap[addr].md5[key][1] = dataMap[addr].md5[key][1].(int) + 2
					fmt.Println("skip: " + info.Name())
					return nil
				}
				// 文件传输
				body := fileBody{CommonBody{auth, time.Now().Unix()}, info.Name(), string(r), to, subPath}
				j, err := json.Marshal(body)
				if err != nil {exit("encode json failed: " + err.Error())}
				fmt.Print("send: " + info.Name() + "   ")
				rsp, err := http.Post("http://" + addr + "/miniw/autoRun?cmd=sendFolder", "", strings.NewReader(base64.StdEncoding.EncodeToString(AES_CBC_encrypt(j))))
				if err != nil {exit("send file " + path + " error:" + err.Error())}
				defer rsp.Body.Close()
				r, err = ioutil.ReadAll(rsp.Body)
				if err != nil {exit("read response body error: " + err.Error())}
				if len(r) == 0 {	// 返回空代表正常
					fmt.Println("ok")
					if !ok {
						dataMap[addr].md5[key] = []interface{}{}
						dataMap[addr].md5[key] = append(dataMap[addr].md5[key], code)
						dataMap[addr].md5[key] = append(dataMap[addr].md5[key], 2)
					} else {
						if arr[0].(string) == code {
							dataMap[addr].md5[key][1] = dataMap[addr].md5[key][1].(int) + 2
							fmt.Println("skip: " + info.Name())
							return nil
						} else {
							dataMap[addr].md5[key][0] = code
							dataMap[addr].md5[key][1] = dataMap[addr].md5[key][1].(int) + 2
						}
					}
				} else {
					fmt.Println(string(r))
				}
			}
			return nil
		})
	} else {
		var name string
		if isWindows() {
			name = from[strings.LastIndexByte(from, '\\')+1:]
		} else if isDarwin() {
			name = from[strings.LastIndexByte(from, '/')+1:]
		}
		//if to[len(to)-1:] == "/" {to = to[:len(to)-1]}
		r, err := ioutil.ReadFile(from)
		if err != nil {exit("read file " + from + " error: " + err.Error())}
		// 文件md5校验
		h := md5.New(); h.Write(r)
		code := hex.EncodeToString(h.Sum(nil))
		key := from + "->" + to
		arr, ok := dataMap[addr].md5[key]
		if ok && arr[0].(string) == code {
			dataMap[addr].md5[key][1] = dataMap[addr].md5[key][1].(int) + 2
			fmt.Println("skip: " + name)
			return
		}
		// 文件传输
		body := fileBody{CommonBody{auth, time.Now().Unix()}, name, string(r), to, ""}
		j, err := json.Marshal(body)
		if err != nil {exit("encode json failed: " + err.Error())}
		fmt.Print("send: " + name + "   ")
		rsp, err := http.Post("http://" + addr + "/miniw/autoRun?cmd=sendFile", "", strings.NewReader(base64.StdEncoding.EncodeToString(AES_CBC_encrypt(j))))
		if err != nil {exit("send file " + from + " error: " + err.Error())}
		defer rsp.Body.Close()
		r, err = ioutil.ReadAll(rsp.Body)
		if err != nil {exit("read response body error: " + err.Error())}
		if len(r) == 0 {	// 返回空代表正常
			fmt.Println("ok")
			if !ok {
				dataMap[addr].md5[key] = []interface{}{}
				dataMap[addr].md5[key] = append(dataMap[addr].md5[key], code)
				dataMap[addr].md5[key] = append(dataMap[addr].md5[key], 2)
			} else {
				dataMap[addr].md5[key][0] = code
				dataMap[addr].md5[key][1] = dataMap[addr].md5[key][1].(int) + 2
			}
		} else {
			fmt.Println(string(r))
		}
	}
}

func send_cmd(cmd string) {
	body := cmdBody{CommonBody{auth, time.Now().Unix()}, cmd}
	j, err := json.Marshal(body)
	if err != nil {exit("encode json failed: " + err.Error())}
	fmt.Print("run: " + cmd + "   ")
	rsp, err := http.Post("http://" + addr + "/miniw/autoRun?cmd=runCmd", "", strings.NewReader(base64.StdEncoding.EncodeToString(AES_CBC_encrypt(j))))
	if err != nil {exit("run " + cmd + " error:" + err.Error())}
	defer rsp.Body.Close()
	r, err := ioutil.ReadAll(rsp.Body)
	if err != nil {exit("read response body error: " + err.Error())}
	if len(r) == 0 {
		fmt.Println("ok")
	} else {
		fmt.Println("\nremote log: " + string(r))
	}
}

func AES_CBC_encrypt(msg []byte) []byte {
	block, err := aes.NewCipher(aesKey)
	if err != nil {exit("newCipher error: " + err.Error())}
	blockSize := block.BlockSize()
	padding := blockSize - len(msg) % blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	origData := append(msg, padtext...)
	blockMode := cipher.NewCBCEncrypter(block, aesKey)
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)
	return crypted
}

func exit(msg string) {
	fmt.Println(msg)
	fmt.Println("close in 5 seconds...")
	time.Sleep(time.Second * 5)
	os.Exit(0)
}