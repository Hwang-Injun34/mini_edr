package collector

import (
	"context"
	"strings"
	"sync"
	"time"
	"strconv"
	"fmt"
)

type AuditLogGroup struct {
	ID string 
	Key string 
	UpdatedAt time.Time

	Syscall *SyscallRecord 
	Execve *ExecveRecord 
	Cwd *CwdRecord 
	Paths []*PathRecord 
	ProcTitle *ProcTitleRecord 
	SockAddr *SockAddrRecord

}

type AuditdCollector struct {
	tailEngine *TailEngine 
	outputChan chan *AuditLogGroup
	pendingMap map[string]*AuditLogGroup 
	mapMutex sync.Mutex 
	ctx context.Context 
	cancel context.CancelFunc
	wg sync.WaitGroup
	errChan chan error 
}

// NewAuditdCollector는 AuditdCollector 객체를 생성하고 초기화한다. 
// 이벤트 전송 채널과 Audit ID 기반 조립 대기 저장소(Map)를 생성하며
// Collector의 시작 및 종료를 관리하기 위한 context를 초기화한 후, 
// *AuditdCollector를 반환한다. 
func NewAuditdCollector(tailEngine *TailEngine) *AuditdCollector {
	ctx, cancel := context.WithCancel(context.Background())
	return &AuditdCollector{
		tailEngine: tailEngine,
		outputChan: make(chan *AuditLogGroup, 1000),
		pendingMap: make(map[string]*AuditLogGroup),
		ctx: ctx, 
		cancel: cancel,
		errChan: make(chan error, 50),
	}
}

// ReadyGroups는 조립이 완료된 AuditLogGroup을 전달하는
// 수신 전용 채널을 반환한다. 
func (c *AuditdCollector) ReadyGroups() <- chan *AuditLogGroup{
	return c.outputChan
}


//	Errors는 내부 에러를 전달하기 위한 에러 수신용 채널을 제공한다. 
func(c *AuditdCollector) Errors() <- chan error {
	return c.errChan
}


// Start는 데이터를 수집하여 조립하는 함수와 저장된 저장소(Map)을 청소하는 함수를 시작한다. 
func (c *AuditdCollector) Start() error {
	c.wg.Add(2)

	go c.runAssembleLoop()
	go c.runMapCleanerLoop()

	return nil 
}


// Stop은 context를 통해 함수를 안전하게 멈추는 함수이다. 
func (c *AuditdCollector) Stop(){
	c.cancel()
	c.wg.Wait()
	close(c.outputChan)
	close(c.errChan)
}


// runAssembleLoop는 TailEngine으로부터 로그를 계속 읽는 메인 루프 함수이다. 
// 읽어들인 로그를 Audit Event ID를 식별하고, 
// EventType 확인 -> 필요한 Record Type 확인 -> Record Type에 맞는 필드값들을 파싱하는 역할을 한다.
func (c *AuditdCollector) runAssembleLoop(){
	defer c.wg.Done()
	for {
		select {
		case <- c.ctx.Done():
			return 

		case line, ok := <- c.tailEngine.NextLine(): // 로그를 한 줄씩 읽어들임
			if !ok {
				return 
			}

			// fmt.Println("Collecotr 수신: ", line)
			c.processLine(line)
		}
	}
}


// processLine은 Audit 로그 한 줄을 처리하는 함수이다. 
// 
// 1. Audit ID를 추출하여 동일 이벤트를 식별한다. 
// 2. Record Type(SYSCALL, EVECVE 등)을 판별한다. 
// 3. Record Type에 맞는 구조체로 파싱한다. 
// 4. AuditLogGroup에 저장한다. 
// 5. 필요한 Record가 모두 수집되면 outputChan으로 전달한다. 
func (c * AuditdCollector) processLine(line string) {
	auditID := c.extractAuditID(line)
	// fmt.Println("AuditID: ", auditID)
	if auditID == ""{
		c.reportError(StageAssemble, "processLine.extractAuditID", ErrInvalidFragment, "Audit ID 포맷 누락 원문: "+line)
		return 
	}

	recordType := c.identifyRecordType(line)
	// fmt.Println("RecordType: ", recordType)
	if recordType == ""{
		c.reportError(StageAssemble, "processLine.identifyRecordType", ErrInvalidFragment, "미지원 레코드 타입 식별 불가: "+line)
		return 
	}

	c.mapMutex.Lock()
	defer c.mapMutex.Unlock()
	
	group, exists := c.pendingMap[auditID]

	if !exists {
		group = &AuditLogGroup{
			ID: auditID, 
			UpdatedAt: time.Now(),
		}
		c.pendingMap[auditID] = group 
	}

	group.UpdatedAt = time.Now()

	switch recordType {
	case SYSCALL:
		group.Syscall = c.parseSyscallRecord(line)

		// fmt.Println(group.Syscall.Key)
		if group.Syscall != nil {
			group.Key = group.Syscall.Key
		} 
	
	case EXECVE:
		group.Execve = c.parseExecveRecord(line)

	case CWD:
		group.Cwd = c.parseCwdRecord(line)
		
	case PATH:
		path := c.parsePathRecord(line)
		if path != nil {
			group.Paths = append(group.Paths, path)
		}

	case PROCTITLE:
		group.ProcTitle = c.parseProcTitleRecord(line)

	case SOCKADDR:
		group.SockAddr = c.parseSockAddrRecord(line)

	}

	ready := c.isReadyToAssemble(group)
	if ready {
		select {
		case c.outputChan <- group:
		default:
			c.reportError(StageAssemble, "processLine.ChannelWrite", ErrBufferOverflow, "조립 완료 큐 가득 참. 이벤트 드롭 위기")
		
		}
		delete(c.pendingMap, auditID)
		
	}
}



// isReadyToAssemble은 EventType에 맞게 RecordType이 충족되었는지 확인하는 함수이다. 
// 
// 1. EventRecords에서 "ProcessCreate"를 만들려면 무엇이 필요한지 체크 리스트를 가져온다. 
// 2. AuditLogGroup을 확인하며 필요한 Record Type이 수집되었는지 확인한다. 
func (c *AuditdCollector) isReadyToAssemble(group *AuditLogGroup) bool {
	if group.Key == "" {
		return false
	}

	var eventType EventType

	switch group.Key {

	case "process_create":
		eventType = ProcessCreate

	case "network_connect":
		eventType = NetworkConnect

	case "file_create":
		eventType = FileCreate

	case "file_delete":
		eventType = FileDelete

	case "process_access":
		eventType = ProcessAccess

	case "shadow_access":
		eventType = ShadowAccess

	case "passwd_access":
		eventType = PasswordAccess

	case "privilege_escalation":
		eventType = PrivilegeEscalation

	case "persistence":
		eventType = Persistence

	default:
		return false
	}

	required := EventRecords[eventType]

	for _, record := range required {

		switch record {

		case SYSCALL:
			if group.Syscall == nil {
				return false
			}

		case EXECVE:
			if group.Execve == nil {
				return false
			}

		case CWD:
			if group.Cwd == nil {
				return false
			}

		case PATH:
			if len(group.Paths) == 0 {
				return false 
			}

		case PROCTITLE:
			if group.ProcTitle == nil {
				return false
			}

		case SOCKADDR:
			if group.SockAddr == nil {
				return false
			}
		}
	}

	return true
}


func (c *AuditdCollector) reportError(stage PipelineStage, comp string, err error, detail string) {
	select {
		case c.errChan <- &EDRError{
			Stage: stage,
			Component: comp,
			Err: err,
			Detail: detail,
		}:
		default:
			fmt.Printf("[OOM Warning] %s -> %s 내부 알림 큐 포화 상태.\n", stage, comp)
	}
}


//============================================================
// 	Record Parser
//============================================================
func (c *AuditdCollector) parseSyscallRecord(line string) *SyscallRecord{
	return &SyscallRecord{
		Success: c.parseStringField(line, "success=") == "yes",
		Exit:    c.parseIntField(line, "exit="),
		PID:     c.parseIntField(line, "pid="),
		PPID:    c.parseIntField(line, "ppid="),
		UID:     c.parseIntField(line, "uid="),
		EUID:    c.parseIntField(line, "euid="),
		GID:     c.parseIntField(line, "gid="),
		Command: c.parseStringField(line, "comm="),
		Exe:     c.parseStringField(line, "exe="),
		TTY:     c.parseStringField(line, "tty="),
		Key:     c.parseStringField(line, "key="),
	}
}

func (c *AuditdCollector) parseExecveRecord(line string) *ExecveRecord{
	argc := c.parseIntField(line, "argc=")
	if argc <= 0 {
		c.reportError(StageAssemble, "parseExecveRecord", ErrInvalidFragment, "EXECVE 레코드의 argc 파싱 실패 혹은 0개 명시: "+line)
		return &ExecveRecord{Argc: 0, Args: []string{}}	
	}
	args := make([]string, 0, argc)

	for i := 0; i < argc; i++ {
		key := fmt.Sprintf("a%d=", i)
		val := c.parseStringField(line, key)
		if val == "" && i > 0 {
			c.reportError(StageAssemble, "parseExecveRecord.Loop", ErrInvalidFragment, fmt.Sprintf("argc는 %d개이나 a%d 필드가 유실되었습니다.", argc, i))
			break
		}
		
		args = append(args, val)
	}

	return &ExecveRecord{
		Argc: argc,
		Args: args,
	}
}

func (c *AuditdCollector) parseCwdRecord(line string) *CwdRecord{
	return &CwdRecord{
		Directory: c.parseStringField(line, "cwd="),
	}
}

func (c *AuditdCollector) parsePathRecord(line string) *PathRecord{
	return &PathRecord{
		Name: c.parseStringField(line, "name="),
		Item: c.parseIntField(line, "item="),
		NameType: c.parseStringField(line, "nametype="),
	}
}

func (c *AuditdCollector) parseProcTitleRecord(line string) *ProcTitleRecord{
	return &ProcTitleRecord{
		Title: c.parseStringField(line, "proctitle="),
	}
}

func (c *AuditdCollector) parseSockAddrRecord(line string) *SockAddrRecord{
	return &SockAddrRecord{
		Address: c.parseStringField(line, "address="),
	}
}


//============================================================
// 	내부 함수
//============================================================
// extractAuditID는 Audit Event ID를 문자열에서 식별하여 반환하는 함수이다. 
func (c *AuditdCollector) extractAuditID(line string) string {
	idx := strings.Index(line, "msg=audit(") // 13
	if idx == -1 {
		return ""
	}

	start := idx + len("msg=audit(") // 13 + 10 
	end := strings.Index(line[start:], ")")
	if end == -1 {
		return ""
	}

	return line[start:start+end]
}

// identifyRecordType은 Audit Record의 타입을 식별하여 해당 RecordType을 반환하는 함수이다.
func (c *AuditdCollector) identifyRecordType(line string) RecordType {
	switch {
	case strings.Contains(line, "type=SYSCALL"):
		return SYSCALL

	case strings.Contains(line, "type=EXECVE"):
		return EXECVE

	case strings.Contains(line, "type=CWD"):
		return CWD

	case strings.Contains(line, "type=PATH"):
		return PATH 

	case strings.Contains(line, "type=PROCTITLE"):
		return PROCTITLE

	case strings.Contains(line, "type=SOCKADDR"):
		return SOCKADDR
	}

	return ""
}


// parseStringField는 문자열에서 특정 값을 식별하는 함수이다. 
func (c *AuditdCollector) parseStringField(line, key string) string {

	idx := strings.Index(line, key)
	if idx == -1 {
		return ""
	}

	start := idx + len(key)

	// 문자열이면
	if start < len(line) && line[start] == '"' {

		start++

		end := strings.Index(line[start:], "\"")
		if end == -1 {
			return ""
		}

		return line[start : start+end]
	}

	// 숫자나 yes/no 같은 값
	end := strings.Index(line[start:], " ")
	if end == -1 {
		return line[start:]
	}

	return line[start : start+end]
}


// parseIntField는 Audit Record에서 지정한 필드의 값을 추출한 후, 
// 문자열을 정수(int)로 변환하여 반환하는 함수이다. 
func (c *AuditdCollector) parseIntField(line, key string) int {
	value := c.parseStringField(line, key)
	n, _ := strconv.Atoi(value)
	return n
}


// runMapCleanerLoop는 15초마다 오래된 조립 대기 이벤트를 제거한다. 
// UpdateAt과 현재 시간이 1분 이상 차이가 나면 삭제한다. 
// *추후 동시성을 위해 수정할 예정*
func(c *AuditdCollector) runMapCleanerLoop(){
	defer c.wg.Done()

	ticker := time.NewTicker(15* time.Second)
	defer ticker.Stop()

	for {
		select {
		case <- c.ctx.Done():
			return 
		case <- ticker.C:
			c.mapMutex.Lock()
			now := time.Now()
			for id, group := range c.pendingMap{
				if now.Sub(group.UpdatedAt) > time.Minute {
					c.reportError(StageAssemble, "runMapCleanerLoop", ErrMissingRequired, fmt.Sprintf("감사 ID: %s 조립 시간 초과 탈락 (수집된 레코드 수 미달)", id))
					delete(c.pendingMap, id)
				}
			}
			c.mapMutex.Unlock()
		}
	}
}


/*
===========================================
	참고 자료
===========================================
-------------------------------------------
	SYSCALL 
-------------------------------------------
type=SYSCALL msg=audit(1782750557.834:45388): 
arch=c000003e 
syscall=59 
success=yes 
exit=0 
a0=561dd89bf5e0 
a1=561dd89ba520 
a2=561dd8983e80 
a3=8 
items=2 
ppid=1666 
pid=20453 
auid=1000 
uid=0 
gid=0 
euid=0 
suid=0 
fsuid=0 
egid=0 
sgid=0 
fsgid=0 
tty=pts0 
ses=3 
comm="tail" 
exe="/usr/bin/tail" 
subj=unconfined 
key=“process_create"
ARCH=x86_64 
SYSCALL=execve 

-------------------------------------------
	EXECVE
-------------------------------------------
type=EXECVE msg=audit(1782753753.194:50765): 
argc=2 
a0="ls" 
a1="--color=auto"

-------------------------------------------
	CWD
-------------------------------------------
type=CWD msg=audit(1782753753.194:50765): 
cwd="/home/pumpkinbee/mini_edr"

-------------------------------------------
	PATH
-------------------------------------------
type=PATH msg=audit(1782753753.194:50765): 
item=0 name="/usr/bin/ls" 
inode=4981511 
dev=fd:00 
mode=0100755 
ouid=0 ogid=0 
rdev=00:00 
nametype=NORMAL 
cap_fp=0 
cap_fi=0 
cap_fe=0 
cap_fver=0 
cap_frootid=0OUID="root" 
OGID="root"

-------------------------------------------
	PROCTITLE
-------------------------------------------
type=PROCTITLE msg=audit(1782753753.194:50765): proctitle=6C73002D2D636F6C6F723D6175746F

*/
