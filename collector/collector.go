package collector


type Collector interface{
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
	Start() error 
	Stop()
	ReadyGroups() <- chan *AuditLogGroup 
	Errors() <- chan error
}