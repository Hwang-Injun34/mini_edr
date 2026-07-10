package dispatcher

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"strconv"
	"encoding/hex"

	"mini_edr/collector"
	"mini_edr/model"
)

type EventDispatcher struct {
	inputChan  <-chan *collector.AuditLogGroup
	outputChan chan *model.SystemEvent
	errChan    chan error
}

// NewEventDispatcher는 EventDispatcher 객체를 생성하고 초기화한다.
// 입력을 받을 inputChan과 출력할 outputChan을 선언한다.
func NewEventDispatcher(inputChan <-chan *collector.AuditLogGroup) *EventDispatcher {
	return &EventDispatcher{
		inputChan:  inputChan,
		outputChan: make(chan *model.SystemEvent, 1000),
		errChan:    make(chan error, 50),
	}
}

// ParsedEvents는 최종 가공이 완료된 SystemEvent 채널을 외부에 제공한다.
func (d *EventDispatcher) ParsedEvents() <-chan *model.SystemEvent {
	return d.outputChan
}

// Errors는 3단계 가공 중 발생한 예외 상황을 모니터링할 수 있도록 에러 채널을 제공한다.
func (d *EventDispatcher) Errors() <-chan error {
	return d.errChan
}

// Start는 변환 루프를 구동한다.
func (d *EventDispatcher) Start(ctx context.Context, wg *sync.WaitGroup) {
	wg.Add(1)
	go d.runTransformLoop(ctx, wg)
}

// runTransformLoop는 입력 채널(Input Channel)을 계속 감시하다가 이벤트가 들어오면,
// 필요한 형태로 데이터를 변환(매핑)하고, 위협 탐지에 필요한 정보만 추출하여 다음 단계로 전달하는 반복 루프이다.
func (d *EventDispatcher) runTransformLoop(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	var sequenceID uint64 = 0

	for {
		select {
		case <-ctx.Done():
			close(d.outputChan)
			close(d.errChan)
			return

		case group, ok := <-d.inputChan:
			if !ok {
				return
			}

			if group.Syscall == nil {
				continue
			}

			sequenceID++
			event := d.buildBaseEvent(group, sequenceID)
			d.enrichEventByKey(event, group)

			select {
			case d.outputChan <- event:
			default:
				d.reportError(
					collector.PipelineStage(StageTransform),
					"runTransformLoop.Output",
					collector.ErrBufferOverflow,
					"4단계 룰 엔진 버퍼 포화로 인한 이벤트 유실 위험",
				)
				return
			}
		}
	}
}

// ====================================================================
// Base Event 생성
// ====================================================================
func (d *EventDispatcher) buildBaseEvent(group *collector.AuditLogGroup, sequenceID uint64,) *model.SystemEvent {
	event := &model.SystemEvent{
		// --------------------------------
		// 공통 메타 정보
		// --------------------------------
		ID:       sequenceID,
		Time:     time.Now(),
		AuditKey: group.Key,

		// --------------------------------
		// 시스템 콜 정보
		// --------------------------------
		SyscallName: group.Syscall.SyscallName,
		Success:     group.Syscall.Success,
		Exit:        group.Syscall.Exit,

		// --------------------------------
		// 프로세스 및 사용자 정보
		// --------------------------------
		PID:  group.Syscall.PID,
		PPID: group.Syscall.PPID,

		UID:  group.Syscall.UID,
		EUID: group.Syscall.EUID,
		GID:  group.Syscall.GID,
		EGID: group.Syscall.EGID,

		ProcessName: d.extractProcessName(group.Syscall.Exe),
		ImagePath:   group.Syscall.Exe,
		ParentImage: d.resolveProcessExe(group.Syscall.PPID),
	}

	// CWD는 이벤트에 따라 누락될 수 있으므로 nil 검사 후 저장한다.
	if group.Cwd != nil {
		event.CurrentDir = group.Cwd.Directory
	}

	return event
}

// ====================================================================
// EventType별 상세 필드 보강
// ====================================================================
func (d *EventDispatcher) enrichEventByKey(event *model.SystemEvent, group *collector.AuditLogGroup) {
	switch group.Key {
	case "process_create":
		d.enrichProcessCreate(event, group)

	case "file_create":
		event.Type = collector.FileCreate
		d.enrichFileEvent(event, group)

	case "file_delete":
		event.Type = collector.FileDelete
		d.enrichFileEvent(event, group)

	case "network_connect":
		d.enrichNetworkConnect(event, group)

	case "persistence":
		d.enrichPersistence(event, group)

	case "privilege_escalation":
		d.enrichPrivilegeEscalation(event, group)

	case "process_access":
		d.enrichProcessAccess(event, group)

	case "shadow_access":
		event.Type = collector.ShadowAccess
		d.enrichFileEvent(event, group)

	case "passwd_access":
		event.Type = collector.PasswordAccess
		d.enrichFileEvent(event, group)

	default:
		event.Type = collector.UnknownEvent
	}
}


func (d *EventDispatcher) enrichProcessCreate(event *model.SystemEvent, group *collector.AuditLogGroup) {
	event.Type = collector.ProcessCreate
	event.CommandLine = d.cleanCommandLine(group.Execve)
}


func (d *EventDispatcher) enrichFileEvent(event *model.SystemEvent, group *collector.AuditLogGroup) {
	event.CommandLine = d.cleanCommandLine(group.Execve)
	// PATH 레코드에서 대상 경로, 파일명, 확장자를 채움
	d.bindPathFields(event, group)

}

func (d *EventDispatcher) enrichNetworkConnect(event *model.SystemEvent, group *collector.AuditLogGroup) {
	event.Type = collector.NetworkConnect
	event.CommandLine = d.cleanCommandLine(group.Execve)

	if group.SockAddr == nil {
		return
	}

	event.DstIP = group.SockAddr.IP
	event.DstPort = group.SockAddr.Port
	event.Protocol = group.SockAddr.Family

	event.TargetFile = group.SockAddr.IP
}

func (d *EventDispatcher) enrichPersistence(event *model.SystemEvent, group *collector.AuditLogGroup) {
	event.Type = collector.Persistence
	event.CommandLine = d.cleanCommandLine(group.Execve)
	d.bindPathFields(event, group)
}

func (d *EventDispatcher) enrichPrivilegeEscalation(event *model.SystemEvent, group *collector.AuditLogGroup) {
	event.Type = collector.PrivilegeEscalation
	event.CommandLine = d.cleanCommandLine(group.Execve)

	if event.CommandLine == "" && group.ProcTitle != nil {
		event.CommandLine = d.decodeProcTitle(group.ProcTitle.Title)
	}
}

func (d *EventDispatcher) enrichProcessAccess(event *model.SystemEvent, group *collector.AuditLogGroup) {
	event.Type = collector.ProcessAccess

	// ptrace(request, pid, addr, data)
	// a0 = request
	if len(group.Syscall.Args) > 0 {
		event.Request = d.ptraceRequestName(group.Syscall.Args[0])
	}

	// a1 = 접근 대상 PID
	if len(group.Syscall.Args) > 1 {
		event.TargetPID = d.parseSyscallPID(group.Syscall.Args[1])
	}

	if group.ProcTitle != nil {
		event.CommandLine = group.ProcTitle.Title
	}
}


// ====================================================================
// 공통 보조 함수
// ====================================================================

func (d *EventDispatcher) bindPathFields(event *model.SystemEvent, group *collector.AuditLogGroup) {
	targetPath := d.selectTargetPath(event.Type, group.Paths)
	if targetPath == nil {
		return
	}

	event.TargetFile = targetPath.Name
	event.PathName = targetPath.Name
	event.FileExt = filepath.Ext(targetPath.Name)
}


func (d *EventDispatcher) cleanCommandLine(execve *collector.ExecveRecord) string {
	if execve == nil || len(execve.Args) == 0 {
		return ""
	}

	var builder strings.Builder

	for i, arg := range execve.Args {
		if arg == "" {
			continue
		}

		if i > 0 {
			builder.WriteString(" ")
		}

		builder.WriteString(arg)
	}

	return builder.String()
}

func (d *EventDispatcher) extractProcessName(path string) string {
	if path == "" {
		return "unknown"
	}

	parts := strings.Split(path, "/")
	if len(parts) == 0 {
		return path
	}

	return parts[len(parts)-1]
}

func (d *EventDispatcher) resolveProcessExe(pid int) string {
	if pid <= 0 {
		return ""
	}

	exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err == nil {
		return exe
	}

	comm, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err == nil {
		name := strings.TrimSpace(string(comm))
		if name != "" {
			return name
		}
	}

	cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err == nil {
		parts := strings.Split(string(cmdline), "\x00")
		if len(parts) > 0 && parts[0] != "" {
			return parts[0]
		}
	}

	return ""
}

func (d *EventDispatcher) ptraceRequestName(a0 string) string {
	switch strings.ToLower(a0) {
	case "10", "0xa":
		return "PTRACE_ATTACH"
	case "2", "0x2":
		return "PTRACE_PEEKDATA"
	case "1", "0x1":
		return "PTRACE_PEEKTEXT"
	case "5", "0x5":
		return "PTRACE_POKEDATA"
	case "4", "0x4":
		return "PTRACE_POKETEXT"
	case "7", "0x7":
		return "PTRACE_CONT"
	case "24", "0x18":
		return "PTRACE_SYSCALL"
	default:
		return a0
	}
}

func (d *EventDispatcher) parseSyscallPID(value string) int {
	if value == "" {
		return 0
	}

	// auditd의 a1 값이 10진수로 들어오는 경우
	pid, err := strconv.Atoi(value)
	if err == nil {
		return pid
	}

	// 0x 접두사가 있는 16진수 값
	if strings.HasPrefix(strings.ToLower(value), "0x") {
		n, err := strconv.ParseInt(value[2:], 16, 64)
		if err == nil {
			return int(n)
		}
	}

	return 0
}

func (d *EventDispatcher) reportError(stage collector.PipelineStage, comp string, err error, detail string) {
	select {
	case d.errChan <- &collector.EDRError{
		Stage:     stage,
		Component: comp,
		Err:       err,
		Detail:    detail,
	}:
	default:
		fmt.Printf("[Dispatcher Error Overload] %s -> %s 알림 유실\n", stage, comp)
	}
}

	
func (d *EventDispatcher) selectTargetPath(
	eventType collector.EventType,
	paths []*collector.PathRecord,
) *collector.PathRecord {
	if len(paths) == 0 {
		return nil
	}

	// 이벤트 유형에 따라 가장 우선적으로 선택할 nametype
	preferredNameType := ""

	switch eventType {
	case collector.FileCreate:
		preferredNameType = "CREATE"

	case collector.FileDelete:
		preferredNameType = "DELETE"

	case collector.Persistence:
		// Audit watch 기반 수정 이벤트는 CREATE가 아니라 NORMAL로 들어올 수도 있다.
		preferredNameType = "NORMAL"

	case collector.ShadowAccess, collector.PasswordAccess:
		preferredNameType = "NORMAL"
	}

	// 1순위: 이벤트에 맞는 nametype 선택
	if preferredNameType != "" {
		for _, path := range paths {
			if path == nil {
				continue
			}

			if strings.EqualFold(path.NameType, preferredNameType) {
				return path
			}
		}
	}

	// 2순위: PARENT가 아닌 실제 대상 경로 선택
	for _, path := range paths {
		if path == nil {
			continue
		}

		if !strings.EqualFold(path.NameType, "PARENT") && path.Name != "" {
			return path
		}
	}

	// 마지막 fallback
	for _, path := range paths {
		if path != nil && path.Name != "" {
			return path
		}
	}

	return nil
}


func (d *EventDispatcher) decodeProcTitle(value string) string {
	if value == "" {
		return ""
	}

	decoded, err := hex.DecodeString(value)
	if err != nil {
		return value
	}

	// PROCTITLE은 인자 사이를 NULL 문자로 구분한다.
	result := strings.ReplaceAll(string(decoded), "\x00", " ")
	return strings.TrimSpace(result)
}