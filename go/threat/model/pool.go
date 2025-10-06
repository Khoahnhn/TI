package model

type (
	PoolAlert struct {
		Details       chan *TTIAlertDetailExport
		Target        string
		Alert         TTIAlert
		Configuration TTIConfig
		Lang          string
	}
)
