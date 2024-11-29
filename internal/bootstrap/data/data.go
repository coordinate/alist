package data

import "github.com/coordinate/alist/cmd/flags"

func InitData() {
	initUser()
	initSettings()
	initTasks()
	if flags.Dev {
		initDevData()
		initDevDo()
	}
}
