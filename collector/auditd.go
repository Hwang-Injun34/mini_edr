package collector

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/binary"
	"net"
	"syscall"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

type AuditLogGroup struct {
	ID        string
	Key       string
	UpdatedAt time.Time

	Syscall   *SyscallRecord   // 시스템 콜 정보
	Execve    *ExecveRecord    // 실행 인자
	Cwd       *CwdRecord       // 현재 작업 디렉터리
	Paths     []*PathRecord    // 접급한 파일 정보
	ProcTitle *ProcTitleRecord // 실행 명령 전체
	SockAddr  *SockAddrRecord  // 네트워크 주소
}

type AuditdCollector struct {
	tailEngine *TailEngine
	outputChan chan *AuditLogGroup
	pendingMap map[string]*AuditLogGroup
	mapMutex   sync.Mutex
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	errChan    chan error
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
		ctx:        ctx,
		cancel:     cancel,
		errChan:    make(chan error, 50),
	}
}

// ReadyGroups는 조립이 완료된 AuditLogGroup을 전달하는
// 수신 전용 채널을 반환한다.
func (c *AuditdCollector) ReadyGroups() <-chan *AuditLogGroup {
	return c.outputChan
}

// Errors는 내부 에러를 전달하기 위한 에러 수신용 채널을 제공한다.
func (c *AuditdCollector) Errors() <-chan error {
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
func (c *AuditdCollector) Stop() {
	c.cancel()
	c.wg.Wait()
	close(c.outputChan)
	close(c.errChan)
}

// runAssembleLoop는 TailEngine으로부터 로그를 계속 읽는 메인 루프 함수이다.
// 읽어들인 로그를 Audit Event ID를 식별하고,
// EventType 확인 -> 필요한 Record Type 확인 -> Record Type에 맞는 필드값들을 파싱하는 역할을 한다.
func (c *AuditdCollector) runAssembleLoop() {
	defer c.wg.Done()
	for {
		select {
		case <-c.ctx.Done():
			return

		case line, ok := <-c.tailEngine.NextLine(): // 로그를 한 줄씩 읽어들임
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
func (c *AuditdCollector) processLine(line string) {
	auditID := c.extractAuditID(line)
	// fmt.Println("AuditID: ", auditID)
	if auditID == "" {
		c.reportError(StageAssemble, "processLine.extractAuditID", ErrInvalidFragment, "Audit ID 포맷 누락 원문: "+line)
		return
	}

	recordType := c.identifyRecordType(line)
	// fmt.Println("RecordType: ", recordType)
	if recordType == "" {

		return
	}

	c.mapMutex.Lock()
	defer c.mapMutex.Unlock()

	group, exists := c.pendingMap[auditID]

	if !exists {
		group = &AuditLogGroup{
			ID:        auditID,
			UpdatedAt: time.Now(),
		}
		c.pendingMap[auditID] = group
	}

	group.UpdatedAt = time.Now()

	switch recordType {
	case SYSCALL:
		group.Syscall = c.parseSyscallRecord(line)

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
			c.reportError(StageAssemble, "processLine.ChannelWrite", ErrBufferOverflow, "조립 완료 큐 가득 참.\n이벤트 드롭 위기")

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
		Stage:     stage,
		Component: comp,
		Err:       err,
		Detail:    detail,
	}:
	default:
		fmt.Println()
		fmt.Printf("[OOM Warning] %s -> %s 내부 알림 큐 포화 상태.\n", stage, comp)
	}
}

//============================================================
// 	Record Parser
//============================================================

// --------------------------------
// SYSCALL Parser
// --------------------------------
func (c *AuditdCollector) parseSyscallRecord(line string) *SyscallRecord {
	args := make([]string, 0, 6)

	for i := 0; i < 6; i++ {
		key := fmt.Sprintf("a%d=", i)
		val := c.parseStringField(line, key)

		if val == "" {
			continue
		}

		args = append(args, val)
	}

	return &SyscallRecord{
		Arch:        c.parseStringField(line, "arch="),
		Syscall:     c.parseIntField(line, "syscall="),
		SyscallName: c.parseStringField(line, "SYSCALL="),

		Success: c.parseStringField(line, "success=") == "yes",
		Exit:    c.parseIntField(line, "exit="),

		Args:  args,
		Items: c.parseIntField(line, "items="),

		PID:  c.parseIntField(line, "pid="),
		PPID: c.parseIntField(line, "ppid="),

		AUID:  c.parseIntField(line, "auid="),
		UID:   c.parseIntField(line, "uid="),
		EUID:  c.parseIntField(line, "euid="),
		GID:   c.parseIntField(line, "gid="),
		EGID:  c.parseIntField(line, "egid="),
		SUID:  c.parseIntField(line, "suid="),
		FSUID: c.parseIntField(line, "fsuid="),
		SGID:  c.parseIntField(line, "sgid="),
		FSGID: c.parseIntField(line, "fsgid="),

		TTY:     c.parseStringField(line, "tty="),
		Session: c.parseIntField(line, "ses="),

		Command: c.parseStringField(line, "comm="),
		Exe:     c.parseStringField(line, "exe="),
		Subject: c.parseStringField(line, "subj="),
		Key:     c.parseStringField(line, "key="),
	}
}

// --------------------------------
// EXECVE Parser
// --------------------------------
func (c *AuditdCollector) parseExecveRecord(line string) *ExecveRecord {
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

// --------------------------------
// CWD Parser
// --------------------------------
func (c *AuditdCollector) parseCwdRecord(line string) *CwdRecord {
	return &CwdRecord{
		Directory: c.parseStringField(line, "cwd="),
	}
}

// --------------------------------
// PATH Parser
// --------------------------------
func (c *AuditdCollector) parsePathRecord(line string) *PathRecord {
	return &PathRecord{
		Item: c.parseIntField(line, "item="),
		Name: c.parseStringField(line, "name="),

		Inode: c.parseIntField(line, "inode="),
		Dev:   c.parseStringField(line, "dev="),
		Mode:  c.parseStringField(line, "mode="),

		OUID: c.parseIntField(line, "ouid="),
		OGID: c.parseIntField(line, "ogid="),

		RDev:     c.parseStringField(line, "rdev="),
		NameType: c.parseStringField(line, "nametype="),

		CapFP:      c.parseStringField(line, "cap_fp="),
		CapFI:      c.parseStringField(line, "cap_fi="),
		CapFE:      c.parseStringField(line, "cap_fe="),
		CapFVer:    c.parseStringField(line, "cap_fver="),
		CapFRootID: c.parseStringField(line, "cap_frootid="),

		OwnerUser:  c.parseStringField(line, "OUID="),
		OwnerGroup: c.parseStringField(line, "OGID="),
	}
}

// --------------------------------
// PROCTITLE Parser
// --------------------------------
func (c *AuditdCollector) parseProcTitleRecord(line string) *ProcTitleRecord {
	return &ProcTitleRecord{
		Title: c.parseStringField(line, "proctitle="),
	}
}

// --------------------------------
// SOCKADDR Parser
// --------------------------------
func (c *AuditdCollector) parseSockAddrRecord(
	line string,
) *SockAddrRecord {
	raw := c.parseHexField(line, "saddr=")

	record := &SockAddrRecord{
		RawAddress: raw,
	}

	if raw == "" {
		fmt.Printf("[SOCKADDR Debug] saddr 추출 실패: %s\n", line)
		return record
	}

	decoded, err := hex.DecodeString(raw)
	if err != nil {
		fmt.Printf(
			"[SOCKADDR Debug] hex 해석 실패: raw=%s err=%v\n",
			raw,
			err,
		)
		return record
	}

	if len(decoded) < 2 {
		return record
	}

	family := binary.LittleEndian.Uint16(decoded[0:2])

	switch family {
	case syscall.AF_INET:
		if len(decoded) < 8 {
			return record
		}

		record.Family = "inet"
		record.Port = int(binary.BigEndian.Uint16(decoded[2:4]))
		record.IP = net.IP(decoded[4:8]).String()

	case syscall.AF_INET6:
		if len(decoded) < 24 {
			return record
		}

		record.Family = "inet6"
		record.Port = int(binary.BigEndian.Uint16(decoded[2:4]))
		record.IP = net.IP(decoded[8:24]).String()

	case syscall.AF_UNIX:
		record.Family = "unix"

		// sockaddr_un에서 2바이트 뒤부터 Unix Socket 경로가 시작된다.
		if len(decoded) > 2 {
			socketPath := decoded[2:]

			if nullIndex := bytes.IndexByte(socketPath, 0); nullIndex >= 0 {
				socketPath = socketPath[:nullIndex]
			}

			record.IP = string(socketPath)
		}

	default:
		record.Family = fmt.Sprintf("unknown(%d)", family)
	}

	fmt.Printf(
		"[SOCKADDR Debug] Raw=%s Family=%s IP=%s Port=%d\n",
		record.RawAddress,
		record.Family,
		record.IP,
		record.Port,
	)

	return record
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

	return line[start : start+end]
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
	searchStart := 0

	for {
		idx := strings.Index(line[searchStart:], key)
		if idx == -1 {
			return ""
		}

		idx += searchStart

		// key 앞 문자가 필드 구분자인지 확인
		// 예: " pid="는 OK, "ppid=" 안의 "pid="는 거부
		if idx > 0 {
			prev := line[idx-1]
			if prev != ' ' && prev != ':' {
				searchStart = idx + len(key)
				continue
			}
		}

		start := idx + len(key)

		// 문자열 값
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
}

// parseIntField는 Audit Record에서 지정한 필드의 값을 추출한 후,
// 문자열을 정수(int)로 변환하여 반환하는 함수이다.
func (c *AuditdCollector) parseIntField(line, key string) int {
	value := c.parseStringField(line, key)
	if value == "" {
		return 0
	}

	n, err := strconv.Atoi(value)
	if err != nil {
		return 0
	}

	return n
}

// decodeSockAddr는 SOCKADDR 로그의 값을 처리한다.
func decodeSockAddr(raw string) (family string, ip string, port int) {
	if raw == "" {
		return "", "", 0
	}

	b, err := hex.DecodeString(raw)
	if err != nil {
		return "", "", 0
	}

	// sockaddr_in 최소 구조:
	// family 2바이트 + port 2바이트 + IPv4 4바이트 = 최소 8바이트
	if len(b) < 8 {
		return "", "", 0
	}

	// AF_INET = 2
	// auditd saddr 예시:
	// 02 00 00 50 8E FB 77 64 ...
	if b[0] == 0x02 && b[1] == 0x00 {
		family = "inet"

		// port는 network byte order(big endian)
		port = int(b[2])<<8 | int(b[3])

		ip = fmt.Sprintf("%d.%d.%d.%d", b[4], b[5], b[6], b[7])

		return family, ip, port
	}

	return "unknown", "", 0
}

// runMapCleanerLoop는 15초마다 오래된 조립 대기 이벤트를 제거한다.
// UpdateAt과 현재 시간이 1분 이상 차이가 나면 삭제한다.
func (c *AuditdCollector) runMapCleanerLoop() {
	defer c.wg.Done()

	// 1. 에이전트가 정상 가동을 시작한 시점을 기록하여 과거 데이터와 분리
	startTime := time.Now()
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.mapMutex.Lock()
			now := time.Now()

			for id, group := range c.pendingMap {
				if now.Sub(group.UpdatedAt) > time.Minute {
					// 2. 에이전트 시작(startTime) 이후에 들어온 실시간 파편이 조립 실패했을 때만 에러 리포트 발행
					if group.UpdatedAt.After(startTime) {
						c.reportError(StageAssemble, "runMapCleanerLoop", ErrMissingRequired, fmt.Sprintf("감사 ID: %s 조립 시간 초과 탈락 (수집된 레코드 수 미달)\n", id))
					}
					// 과거에 밀려있던 잔여 찌꺼기 데이터들은 경고 없이 조용히 맵에서만 삭제(메모리 해제)
					delete(c.pendingMap, id)
				}
			}
			c.mapMutex.Unlock()
		}
	}
}


// parseHexField는 key 뒤에서 0~9, a~f, A~F에 해당하는
// 연속된 16진수 문자만 추출한다.
//
// 예:
// saddr=02001F917F0000010000000000000000SADDR={
//
// 반환:
// 02001F917F0000010000000000000000
func (c *AuditdCollector) parseHexField(line, key string) string {
	idx := strings.Index(line, key)
	if idx == -1 {
		return ""
	}

	start := idx + len(key)
	end := start

	for end < len(line) {
		ch := line[end]

		isHexDigit :=
			(ch >= '0' && ch <= '9') ||
				(ch >= 'a' && ch <= 'f') ||
				(ch >= 'A' && ch <= 'F')

		if !isHexDigit {
			break
		}

		end++
	}

	if end == start {
		return ""
	}

	return line[start:end]
}