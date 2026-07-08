package collector

// ====================================================================
// EventType 정의 (EDR 사용자 공간 최종 탐지 유형)
// ====================================================================
type EventType string

const (
	ProcessCreate       EventType = "ProcessCreate"
	NetworkConnect      EventType = "NetworkConnect"
	FileCreate          EventType = "FileCreate"
	FileDelete          EventType = "FileDelete"
	ProcessAccess       EventType = "ProcessAccess"
	ShadowAccess        EventType = "ShadowAccess" 		
	PasswordAccess      EventType = "PasswordAccess" 
	PrivilegeEscalation EventType = "PrivilegeEscalation"
	Persistence         EventType = "Persistence"
	UnknownEvent        EventType = "Unknown"
)

// ====================================================================
// RecordType 정의 (audit.log 분할 라인 분류용 접두사)
// ====================================================================
type RecordType string

const (
	SYSCALL   RecordType = "SYSCALL"
	EXECVE    RecordType = "EXECVE"
	CWD       RecordType = "CWD"
	PATH      RecordType = "PATH"
	PROCTITLE RecordType = "PROCTITLE"
	SOCKADDR  RecordType = "SOCKADDR"
)

// ====================================================================
// Event별 필요한 Record 매핑 매트릭스 (완제품 조립 검증용)
// ====================================================================
var EventRecords = map[EventType][]RecordType{
	ProcessCreate: {
		SYSCALL,
		EXECVE,
		CWD,
		PATH,
		PROCTITLE,
	},
	NetworkConnect: {
		SYSCALL,
		SOCKADDR,
		CWD,
		PATH,
	},
	FileCreate: {
		SYSCALL,
		CWD,
		PATH, 
		PROCTITLE,
	},
	FileDelete: {
		SYSCALL,
		CWD,
		PATH,
		PROCTITLE,
	},
	ProcessAccess: {
		SYSCALL,
		PROCTITLE,
	},
	ShadowAccess: {
		SYSCALL,
		CWD,
		PATH,
		PROCTITLE,
	},
	PasswordAccess: {
		SYSCALL,
		CWD,
		PATH,
		PROCTITLE,
	},
	PrivilegeEscalation: {
		SYSCALL,
		PROCTITLE,
	},
	Persistence: {
		SYSCALL,
		CWD,
		PATH,
		PROCTITLE,
	},
}

// ====================================================================
// Record별 정형 데이터 모델 정의 (파서 엔진 매핑용)
// ====================================================================

// SYSCALL 레코드 상세 구조체
type SyscallRecord struct {
	Arch   			string 	`json:"arch"` 
	Syscall 		int    	`json:"syscall"`
	SyscallName 	string  `json:"syscall_name"`

	Success bool   `json:"success"`
	Exit    int    `json:"exit"`

	Args []string  `json:"args"`
	Items   int    `json:"items"`

	PID     int    `json:"pid"`
	PPID    int    `json:"ppid"`

	AUID  int `json:"auid"`
	UID   int `json:"uid"`
	EUID  int `json:"euid"`
	GID   int `json:"gid"`
	EGID  int `json:"egid"`
	SUID  int `json:"suid"`
	FSUID int `json:"fsuid"`
	SGID  int `json:"sgid"`
	FSGID int `json:"fsgid"`
	
	TTY     string `json:"tty"`
	Session int    `json:"session"`
	
	Command string `json:"command"`
	Exe     string `json:"exe"`
	Subject string `json:"subject"`
	Key     string `json:"key"`
}

// EXECVE 레코드 상세 구조체
type ExecveRecord struct {
	Argc int      `json:"argc"`
	Args []string `json:"args"`
}

// CWD 레코드 상세 구조체 (실행 당시 현재 작업 디렉터리)
type CwdRecord struct {
	Directory string `json:"directory"`
}

// PATH 레코드 상세 구조체 (파일 관련 시스템 정보 변수)
type PathRecord struct {
	Item     int    `json:"item"`      
	Name     string `json:"name"`      
	Inode    int    `json:"inode"`     
	Dev      string `json:"dev"`      
	Mode     string `json:"mode"`      

	OUID int `json:"ouid"` 
	OGID int `json:"ogid"` 

	RDev     string `json:"rdev"`      
	NameType string `json:"name_type"` 

	CapFP     string `json:"cap_fp"`
	CapFI     string `json:"cap_fi"`
	CapFE     string `json:"cap_fe"`
	CapFVer   string `json:"cap_fver"`
	CapFRootID string `json:"cap_frootid"`

	OwnerUser  string `json:"owner_user"`  
	OwnerGroup string `json:"owner_group"` 
}

// PROCTITLE 레코드 상세 구조체
type ProcTitleRecord struct {
	Title string `json:"title"`
}

// SOCKADDR 레코드 상세 구조체 (Network 아웃바운드 목적지 IP/Port)
type SockAddrRecord struct {
	RawAddress string `json:"raw_address"`
	
	Family string `json:"family"`
	IP string `json:"ip"`
	Port int  `json:"port"`
}