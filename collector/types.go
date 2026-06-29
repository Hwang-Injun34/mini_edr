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
	PasswordAccess      EventType = "PasswordAccess" // 네이밍 통일 (Password)
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
		PATH, // 중복 표기 제거 후 단일 명시 (인메모리에서 다중 파편으로 수집 처리)
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
	PasswordAccess: { // PasswdAccess 오타 수정 완료
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
	Success bool   `json:"success"`
	Exit    int    `json:"exit"`
	PID     int    `json:"pid"`
	PPID    int    `json:"ppid"`
	UID     int    `json:"uid"`
	EUID    int    `json:"euid"`
	GID     int    `json:"gid"`
	Command string `json:"command"`
	Exe     string `json:"exe"`
	TTY     string `json:"tty"`
	Key     string `json:"key"`
}

// EXECVE 레코드 상세 구조체 (ProcessCreate 명령어 인자용)
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
	Name     string `json:"name"`
	Item     int    `json:"item"`      // int 타입 확정
	NameType string `json:"name_type"` // CREATE, DELETE, NORMAL 등
}

// PROCTITLE 레코드 상세 구조체
type ProcTitleRecord struct {
	Title string `json:"title"`
}

// SOCKADDR 레코드 상세 구조체 (Network 아웃바운드 목적지 IP/Port)
type SockAddrRecord struct {
	Address string `json:"address"`
}