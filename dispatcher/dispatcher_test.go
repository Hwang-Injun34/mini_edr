package dispatcher

import (
	"context"
	"sync"
	"testing"
	"time"

	"mini_edr/collector"
)

func TestEventDispatcher_Transform(t *testing.T) {
	mockInput := make(chan *collector.AuditLogGroup, 10)
	dispatcher := NewEventDispatcher(mockInput)

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup

	// 디스패처 엔진 작동
	dispatcher.Start(ctx, &wg)

	// 2단계 조립기가 완성한 스펙의 목업 가방 생성
	mockGroup := &collector.AuditLogGroup{
		ID:  "777.888:111",
		Key: "process_create",
		Syscall: &collector.SyscallRecord{
			PID:  9999,
			PPID: 1000,
			Exe:  "/usr/bin/nc",
		},
		Execve: &collector.ExecveRecord{
			Argc: 3,
			Args: []string{"nc", "-lvp", "4444"}, // 리버스 쉘 바인딩 시나리오
		},
		Cwd: &collector.CwdRecord{Directory: "/var/www/html"},
	}

	// 데이터 주입
	mockInput <- mockGroup
	close(mockInput)

	// 가공 완제품 대조 검증
	select {
	case finalEvent := <-dispatcher.ParsedEvents():
		if finalEvent.PID != 9999 {
			t.Errorf("PID 이관 매핑 불일치")
		}
		if finalEvent.ProcessName != "nc" {
			t.Errorf("프로세스명 정제 알고리즘 오류: %s", finalEvent.ProcessName)
		}
		expectedCmd := "nc -lvp 4444"
		if finalEvent.CommandLine != expectedCmd {
			t.Errorf("가변 인자 공백 합성 오류. 실제: %s", finalEvent.CommandLine)
		}
		if finalEvent.Type != collector.ProcessCreate {
			t.Errorf("이벤트 유형 식별 레이블 오작동")
		}
	case <-time.After(1 * time.Second):
		t.Fatal("타임아웃: EventDispatcher가 완제품을 생성하지 못했습니다.")
	}

	cancel()
	wg.Wait()
}