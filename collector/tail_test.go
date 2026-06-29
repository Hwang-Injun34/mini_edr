package collector

import (
	"os"
	"testing"
	"time"
)

// AI - TailEngine 생성 테스트
func TestNewTailEngine(t *testing.T) {
	engine := NewTailEngine("/tmp/test.log")

	if engine == nil {
		t.Fatal("TailEngine 생성 실패")
	}

	if engine.logPath != "/tmp/test.log" {
		t.Errorf("로그 경로가 올바르지 않습니다.")
	}

	if engine.lineChan == nil {
		t.Error("lineChan이 생성되지 않았습니다.")
	}
}

// AI - Start / Stop 테스트
func TestTailEngineStartStop(t *testing.T) {

	tmpFile, err := os.CreateTemp("", "tail_test_*.log")
	if err != nil {
		t.Fatalf("임시 파일 생성 실패 : %v", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	engine := NewTailEngine(tmpFile.Name())

	if err := engine.Start(); err != nil {
		t.Fatalf("Start 실패 : %v", err)
	}

	time.Sleep(300 * time.Millisecond)

	engine.Stop()
}