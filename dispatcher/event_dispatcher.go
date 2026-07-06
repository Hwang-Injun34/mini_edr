package dispatcher

import (
	"context"
	"mini_edr/collector"
	"mini_edr/model"
	"strings"
	"sync"
	"time"
	"fmt"
)

type EventDispatcher struct {
	inputChan <- chan *collector.AuditLogGroup
	outputChan chan *model.SystemEvent
	errChan chan error 
}

// NewEventDispatcher는 EventDispatcher 객체를 생성하고 초기화한다.
// 입력을 받을 inputChan과 출력할 outputChan을 선언한다.
func NewEventDispatcher(inputChan <-chan *collector.AuditLogGroup) *EventDispatcher{
	return &EventDispatcher{
		inputChan: inputChan,
		outputChan: make(chan *model.SystemEvent, 1000),
		errChan: make(chan error, 50),
	}
}


// ParsedEvents는 최종 가공이 완료된 SystemEvent 채널을 외부에 제공한다. 
func (d *EventDispatcher) ParsedEvents() <-chan *model.SystemEvent{
	return d.outputChan
}


// Errors는 3단계 가공 중 발생한 예외 상황을 모니터링할 수 있도록 에러 채널을 제공한다.
func (d *EventDispatcher) Errors() <- chan error {
	return d.errChan
}


// Start는 변환 루프를 구동한다. 
func(d *EventDispatcher) Start(ctx context.Context, wg *sync.WaitGroup){
	wg.Add(1)
	go d.runTransformLoop(ctx, wg)
}


// runTransformLoop는 입력 채널(Input Channel)을 계속 감시하다가 이벤트가 들어오면, 
// 필요한 형태로 데이터를 변환(매핑)하고, 위협 탐지에 필요한 정보만 추출하여 다음 단계로 전달하는 반복 루프이다.
func(d *EventDispatcher) runTransformLoop(ctx context.Context, wg *sync.WaitGroup){
	defer wg.Done()
	var sequenceID uint64 = 0

	for {
		select {
		case <-ctx.Done():
			close(d.outputChan)
			close(d.errChan)
			return 
		case group, ok := <-d.inputChan:
			if !ok{
				return 
			}

			if group.Syscall == nil {
				continue
			}
			sequenceID++

			// [1단계] 공통 필드 기본 다이렉트 고속 매핑
			event := &model.SystemEvent{
				ID: sequenceID,
				Time: time.Now(),
				AuditKey: group.Key,
				PID: group.Syscall.PID,
				PPID: group.Syscall.PPID,
				UID: group.Syscall.UID,
				EUID: group.Syscall.EUID,
				ImagePath: group.Syscall.Exe,
			}

			// [2딘계] 규칙 Key별로 맞춤형 특화 데이터 정제 및 레이블링 수행
			switch group.Key{
			case "process_create":
				event.Type = collector.ProcessCreate
				event.ProcessName = d.extractProcessName(event.ImagePath)
				event.CommandLine = d.cleanCommandLine(group.Execve)
				if group.Cwd != nil {
					event.RawMessage = fmt.Sprintf("CWD=%s", group.Cwd.Directory)
				}

			case "file_create", "file_delete":
				if group.Key == "file_create" {
					event.Type = collector.FileCreate
				} else {
					event.Type = collector.FileDelete
				}
				if len(group.Paths) > 0 && group.Paths[0] != nil {
					event.TargetFile = group.Paths[0].Name
				}

			case "network_connect":
				event.Type = collector.NetworkConnect
				if group.SockAddr != nil {
					event.TargetFile = group.SockAddr.Address
				}

			// ─── [★ 신규 확장: 룰 엔진 연계 보안 위협 영역] ───
			case "persistence":
				// 크론탭 등록, 서비스 유닛 파일 조작 등 공격자의 지속성 확보 행위
				event.Type = collector.Persistence
				event.ProcessName = d.extractProcessName(event.ImagePath)
				event.CommandLine = d.cleanCommandLine(group.Execve)
				// 지속성 공격은 어떤 파일을 건드렸는지가 핵심 (TargetFile 바인딩)
				if len(group.Paths) > 0 && group.Paths[0] != nil {
					event.TargetFile = group.Paths[0].Name
				}

			case "privilege_escalation":
				// sudo 권한 남용, 특정 취약점 실행 등 권한 상승 행위 탐지
				event.Type = collector.PrivilegeEscalation
				event.ProcessName = d.extractProcessName(event.ImagePath)
				event.CommandLine = d.cleanCommandLine(group.Execve)

			case "process_access":
				// 타 프로세스 메모리 덤프(lsass 덤프 변형 등)나 권한 침해 행위
				event.Type = collector.ProcessAccess
				event.ProcessName = d.extractProcessName(event.ImagePath)
				// 프로세스 접근의 경우, 어떤 타깃 바이너리에 접근하려 했는지 대조 유도
				if group.ProcTitle != nil {
					event.CommandLine = group.ProcTitle.Title
				}

			case "shadow_access", "passwd_access":
				// /etc/shadow 또는 /etc/passwd 자격 증명 파일에 대한 무단 접근/수정 감시
				if group.Key == "shadow_access" {
					event.Type = collector.ShadowAccess
				} else {
					event.Type = collector.PasswordAccess
				}
				event.ProcessName = d.extractProcessName(event.ImagePath)
				if len(group.Paths) > 0 && group.Paths[0] != nil {
					event.TargetFile = group.Paths[0].Name
				}

			default:
				// 매핑 레이블이 없는 무명 이벤트 방어선
				event.Type = collector.UnknownEvent
			}

			select {
			case d.outputChan <- event:
			default:
				//d.reportError(collector.StageParse, "runTransformLoop.Output", collector.ErrBufferOverflow, "4단계 룰 엔진 버퍼 포화로 인한 이벤트 유실 위험")
				return 
			}


		}

	}
}


// cleanCommandLine은 2단계 가변 파서가 모아둔 Args 배열을 문자열 형태로 결합한다.
func (d *EventDispatcher) cleanCommandLine(execve *collector.ExecveRecord) string {
	if execve == nil || len(execve.Args) == 0 {
		return ""
	}

	var builder strings.Builder
	for i, arg := range execve.Args{
		if arg == ""{
			continue
		}

		if i > 0 {
			builder.WriteString(" ")
		}
		builder.WriteString(arg)
	}
	return builder.String()
}


// extractProcessName은 절대 경로에서 순수 바이너리 파일 이름만 반환한다. 
func (d *EventDispatcher) extractProcessName(path string) string {
	if path == ""{
		return "unknown"
	}
	parts := strings.Split(path, "/")
	if len(parts) == 0 {
		return path
	}
	return parts[len(parts)-1]
}

// 에러 핸들러 연계용 리포터
func (d *EventDispatcher) reportError(stage collector.PipelineStage, comp string, err error, detail string) {
	select {
	case d.errChan <- &collector.EDRError{Stage: stage, Component: comp, Err: err, Detail: detail}:
	default:
		fmt.Printf("[Dispatcher Error Overload] %s -> %s 알림 유실\n", stage, comp)
	}
}