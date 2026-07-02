package collector


type Collecotr interface{
	Start() error
	Stop()
	Errors() <-chan error 
}


type RawLineStreamer interface{
	Start() error 
	Stop() 
	NextLine() <-chan string
	Errors() <- chan error
}

type GroupAssembler interface{
	Strat() error 
	Stop()
	ReadyGroups() <- chan *AuditLogGroup 
	Errors() <- chan error
}