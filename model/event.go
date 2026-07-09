package model

import (
	"time"
	"mini_edr/collector"
)


// ====================================================================
// SystemEvent
// Collector(1~2단계)에서 조립된 Audit 이벤트를 Dispatcher(3단계)가
// Rule Engine이 사용하기 시운 형태로 가공한 최종 이벤트 객체
// 
// 이후 Rule Engine, Alert Dispatcher 등
// 모든 상위 계층이 이 구조체만 사용하여 데이터를 처리한다. 
// ====================================================================
type SystemEvent struct {
	// --------------------------------
	// 공통 메타 정보
	// --------------------------------
	ID        uint64    `json:"id"`        		 // 이벤트 정렬 및 추적을 위한 고유 시퀀스 번호
	Time      time.Time `json:"time"`     		 // Dispatcher에서 이벤트 생성 시각
	Type      collector.EventType `json:"type"`  // 최종 이벤트 유형(ProcessCreate, FileCreate 등)
	AuditKey  string    `json:"audit_key"` 	     // Auditd Rule의 k값 또는 탐지된 Rule ID
	

	// --------------------------------
	// 프로세스 정보
	// --------------------------------
	PID       int       `json:"pid"`			// 현재 실행된 프로세스 ID
	PPID      int       `json:"ppid"`			// 현재 프로세스를 생성한 부모 프로세스 ID

	UID       int       `json:"uid"`			// 실제 사용자 ID
	EUID      int       `json:"euid"`			// 유효 사용자 ID(권한 상승 여부 판단)

	GID 	  int 		`json:"gid"`			// 실제 그룹 ID
	EGID	  int 		`json:"egid"`			// 유효 그룹 ID(Setgid 탐지 등)
 
	ProcessName string `json:"process_name"`	// 순수 실행 파일 이름(예: bash, curl, ls)
	ImagePath   string `json:"image_path"`		// 현재 실행된 바이너리 절대 경로

	ParentImage string `json:"parent_image"`    // 부모 프로세스의 실행 파일 절대 경로
												// ProcessCreate 규칙에서 "ppid_exe" 조건을 평가하기 위해 사용

	// --------------------------------
	// 명령 실행 정보
	// --------------------------------
	CommandLine string `json:"command_line"`	// EXECVE 레코드의 인자를 하나의 문자열로 합친 명령행
	
	// --------------------------------
	// 파일 이벤트 정보
	// --------------------------------
	TargetFile string `json:"target_file"` 		// 접근, 생성, 삭제된 파일의 전체 경로
	PathName   string `json:"pathname"`			// Rule Engine에서 path/pathname 조건 비교에서 사용하는 경로
	FileExt    string `json:"file_ext"`			// 대상 파일의 확장자
	
	// --------------------------------
	// 네트워크 이벤트 정보
	// --------------------------------
	DstIP    string `json:"dst_ip"`				// 목적지 IP 주소
	DstPort  int    `json:"dest_port"`			// 목적지 포트 번호 
	Protocol string `json:"protocol"`			// 통신 프로토콜

	// --------------------------------
	// ProcessAccess / ptrace 상세 정보
	// --------------------------------
	Request string `json:"request"`

	// --------------------------------
	// 내부 디버깅용 원본 데이터
	// --------------------------------
	RawMessage string `json:"-"` 
}