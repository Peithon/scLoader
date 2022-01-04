package core

import "os"

func checkError(err error) {
	//如果内存调用出现错误，可以报错
	if err != nil {
		//如果调用dll系统发出警告，但是程序运行成功，则不进行警报
		if err.Error() != "The operation completed successfully." {
			//报出具体错误
			println(err.Error())
			os.Exit(1)
		}
	}
}
