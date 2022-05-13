package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/fs"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

var (
	logFile *os.File
	logWriter *bufio.Writer
	timestamp = time.Now().Unix()
	rsaPublicKey = []byte("-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC13nLT84uTVJ5/tiTClF/0L+6B\n+/P0FgQpLDN+PvRj92funqWm3lN6eO5ZHtBYZy2cojjIsF9BNaYCGHc2FatnOcs/\nG9o2VkBdf/IBaTDiHwohO5+UssaiT5oXD20EsK9VAbyOhrC9f85Owxm8HvAyEUmK\ncl6W6Fz9C1grGVE9sQIDAQAB\n-----END PUBLIC KEY-----")
	rsaPrivateKey = []byte("-----BEGIN RSA PRIVATE KEY-----\nMIICWwIBAAKBgQC13nLT84uTVJ5/tiTClF/0L+6B+/P0FgQpLDN+PvRj92funqWm\n3lN6eO5ZHtBYZy2cojjIsF9BNaYCGHc2FatnOcs/G9o2VkBdf/IBaTDiHwohO5+U\nssaiT5oXD20EsK9VAbyOhrC9f85Owxm8HvAyEUmKcl6W6Fz9C1grGVE9sQIDAQAB\nAoGAa3HWKP3TUeFGGnFDWmlKHvtKTyTIxUVUg/aHHWiX/Y8mqcS0XNcwPkS/m4sm\nz3N1cPotzfLU87N8NfS6SQuYTM0Zw3uQ5WU/lgFckLAQLlgVAjjAYVtc7/q3NbCj\nHdYD5a6C4CZTiVHxTiLJ6pQJU5PiWqLP91+EmVItm1cakAECQQDydDtZ97RCB4sG\n0+frDQWUfpfEwCXQ8pm3J+/92vrVt/ch7phaAj8g1Q+z/ATJ0quvoVbeIAD2Yeuw\nl4mKHIcxAkEAwAeuXMJ8pJ6fxEcsJburFRUF5vDSXd2jb39BNpC9S45ApZpRdsAV\nar0alk2JpPzkHf2+MluVl3Nb/3L1IRd+gQJAa6mtiV/zjbanx9pli/z2U2B7qITi\nxgxUsf5sFcAdzrWoakr3IFELE1tJY9UvkyeX0Z/FYVG426/T51EDZG8SoQJAMYZJ\nm7a0+qfGQJKyehDKcKd5XDQjrP2qVukU4oO1rjTDy3HfLKchXuPiZX0d0KVAF9QH\nJ2mjTOn9ggYd3ij3AQJAXIX8OuqRhXRMHQC3M2rl/E4GwjQ5pxlvWZBhWoIEWwwn\nZfHjEEyVhuToYpgImQysGDKB/BGn9z7dlQFcegypXQ==\n-----END RSA PRIVATE KEY-----")
)


func server() {
	http.HandleFunc("/miniw/autoRun", handler)
	http.ListenAndServe("0.0.0.0:8899", nil)
}

func handler(w http.ResponseWriter, req *http.Request) {
	req.ParseForm()
	param := req.Form

	switch param["cmd"][0] {
	case "sendFile":
		fmt.Fprint(w, handle_sendFile(req))
	case "sendFolder":
		fmt.Fprint(w, handle_sendFolder(req))
	case "runCmd":
		fmt.Fprint(w, handle_cmd(req))
	case "ping":
		fmt.Fprint(w, "pong")
	case "encrypt":
		fmt.Fprint(w, handle_encrypt(req))
	}
}

func prehandle(req *http.Request, f func([]byte) bodyInter) (bool, string, string) {
	bytes, err := ioutil.ReadAll(req.Body)
	if err != nil {return false, err.Error(), ""}
	bytes, err = base64.StdEncoding.DecodeString(string(bytes))
	if err != nil {return false, err.Error(), ""}
	bytes, err = AES_CBC_decrypt(bytes)
	if err != nil {return false, err.Error(), ""}
	b := f(bytes)
	t := b.time()
	if t < timestamp {return false, "can't recall using same data", ""}
	if VERSION == "release" {
		bytes, err = base64.StdEncoding.DecodeString(b.auth())
		if err != nil {return false, err.Error() , ""}
		ret, user := RSA_decrypt(bytes)
		if !ret {return ret, user, ""}
		timestamp = t
		return true, "", user
	} else {
		timestamp = t
		return true, "", ""
	}
}

func handle_sendFile(req *http.Request) string {
	var body fileBody
	ret, msg, user := prehandle(req, func(bytes []byte) bodyInter {
		json.Unmarshal(bytes, &body)
		return &body
	})
	if !ret {return msg}

	if VERSION == "release" {
		w, errmsg := get_log_file()
		if w == nil {return errmsg}
		w.WriteString(fmt.Sprintf("%s %s|%s|%s/%s\n", time.Now().Format("[2006-01-02 15:04:05]"), user, req.Form["cmd"][0], body.Root, body.Name))
		w.Flush()
	}

	if info, err := os.Stat(body.Root); err != nil {
		if os.IsNotExist(err) {
			if body.Root[len(body.Root)-1:] == "/" {
				return "path not exist"
			}
			index := strings.LastIndexByte(body.Root, '/')
			body.Name = body.Root[index+1:]
			body.Root = body.Root[:index]
			if info, err = os.Stat(body.Root); err != nil {
				if os.IsNotExist(err) {return err.Error()}
				return err.Error()
			}
		} else {return err.Error()}
	} else if (!info.IsDir()) {return "path not exist"} // 路径错误
	// 写文件
	filePath := body.Root + "/" + body.Name
	file, err := os.OpenFile(filePath, os.O_TRUNC|os.O_CREATE|os.O_RDWR, 0666)
	defer file.Close()
	if err != nil {return err.Error()}
	writer := bufio.NewWriter(file)
	writer.WriteString(body.Data)
	writer.Flush()
	return ""
}

func handle_sendFolder(req *http.Request) string {
	var body fileBody
	ret, msg, user := prehandle(req, func(bytes []byte) bodyInter {
		json.Unmarshal(bytes, &body)
		return &body
	})
	if !ret {return msg}

	if VERSION == "release" {
		w, errmsg := get_log_file()
		if w == nil {return errmsg}
		w.WriteString(fmt.Sprintf("%s %s|%s|%s%s/%s\n", time.Now().Format("[2006-01-02 15:04:05]"), user, req.Form["cmd"][0], body.Root, body.Path, body.Name))
		w.Flush()
	}

	// 检查根路径
	if info, err := os.Stat(body.Root); err != nil {
		if os.IsNotExist(err) {
			if body.Root[len(body.Root)-1:] == "/" {
				return "path not exist"
			}
			index := strings.LastIndexByte(body.Root, '/')
			parent := body.Root[:index]
			if info, err := os.Stat(parent); err != nil {
				if os.IsNotExist(err) {return "path not exist"}
			} else if (!info.IsDir()) {return "path not exist"}
			if err = os.Mkdir(body.Root, os.ModePerm); err != nil {return err.Error()}
		} else {return err.Error()}
	} else if !info.IsDir() {
		return "path not exist"
	}

	// 保证子路径有效
	if len(body.Path) > 0 {
		tmpPath := body.Root
		arr := strings.Split(body.Path[1:], "/")
		for _, name := range arr {
			tmpPath += "/" + name
			if _, err := os.Stat(tmpPath); err != nil {
				if !os.IsNotExist(err) {return err.Error()}
				if err = os.Mkdir(tmpPath, os.ModePerm); err != nil {return err.Error()}
			}
		}
	}
	// 写文件
	filePath := body.Root + body.Path + "/" + body.Name
	file, err := os.OpenFile(filePath, os.O_TRUNC|os.O_CREATE|os.O_RDWR, 0666)
	defer file.Close()
	if err != nil {return "open file " + filePath + " error: " + err.Error()}
	writer := bufio.NewWriter(file)
	writer.WriteString(body.Data)
	writer.Flush()
	return ""
}

func handle_cmd(req *http.Request) string {
	var body cmdBody
	ret, msg, user := prehandle(req, func(bytes []byte) bodyInter {
		json.Unmarshal(bytes, &body)
		return &body
	})
	if !ret {return msg}

	if VERSION == "release" {
		w, errmsg := get_log_file()
		if w == nil {return errmsg}
		w.WriteString(fmt.Sprintf("%s %s|%s|%s\n", time.Now().Format("[2006-01-02 15:04:05]"), user, req.Form["cmd"][0], body.Cmd))
		w.Flush()
	}

	res, err := exec.Command("bash", body.Cmd).Output()
	if err != nil {return err.Error()}
	return string(res)
}

func handle_encrypt(req *http.Request) string {
	if strings.Split(req.RemoteAddr, ":")[0] != "127.0.0.1" {
		return "permission denied"
	}
	param := req.Form
	return RSA_encrypt([]byte(param["key"][0])) + "\n"
}

func RSA_encrypt(key []byte) string {
	block, _ := pem.Decode(rsaPublicKey)
	publicKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {return err.Error()}
	publicKey := publicKeyInterface.(*rsa.PublicKey)
	cipherText, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, key)
	if err != nil {return err.Error()}
	return string(base64.StdEncoding.EncodeToString(cipherText))
}

func RSA_decrypt(key []byte) (bool, string) {
	block, _ := pem.Decode(rsaPrivateKey)
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {return false, err.Error()}
	plainText, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, key)
	if err != nil {return false, err.Error()}
	return true, string(plainText)
}

func AES_CBC_decrypt(msg []byte) ([]byte, error) {
	block, err := aes.NewCipher(aesKey)
	if err != nil {return nil, err}
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, aesKey[:blockSize])
	origData := make([]byte, len(msg))
	blockMode.CryptBlocks(origData, msg)
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length-unpadding)], nil
}

func get_log_file() (*bufio.Writer, string) {
	lastName := "/var/log/autoRun_" + time.Now().Format("01-02") + ".log"
	if _, err := os.Stat(lastName); err != nil {
		if os.IsNotExist(err) {
			// 关闭文件
			logFile.Close()
			logWriter = nil
			// 删除过期日志
			firstName := "autoRun_" + time.Now().AddDate(0, 0, -6).Format("01-02") + ".log"
			err := filepath.Walk("/var/log/", func(path string, info fs.FileInfo, err error) error {
				if filepath.Dir(path) != "/var/log" {return nil}
				name := info.Name()
				if strings.HasPrefix(name, "autoRun") && name <= firstName {
					err := os.Remove(path)
					if err != nil {return err}
				}
				return nil
			})
			if err != nil {return nil, err.Error()}
		} else {return nil, err.Error()}
	} else {
		return logWriter, ""
	}
	// 打开今天的日志
	file, err := os.OpenFile(lastName, os.O_CREATE|os.O_RDWR, 0666)
	if err != nil {return nil, err.Error()}
	logFile = file
	logWriter = bufio.NewWriter(file)
	return logWriter, ""
}