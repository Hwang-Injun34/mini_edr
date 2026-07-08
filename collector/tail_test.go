package collector

import (
	"os"
	"testing"
	"time"
)

func TestTailEngineReceivesNewLine(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "audit-test-*.log")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	engine := NewTailEngine(tmpFile.Name())

	if err := engine.Start(); err != nil {
		t.Fatal(err)
	}
	defer engine.Stop()

	time.Sleep(200 * time.Millisecond)

	_, err = tmpFile.WriteString("type=SYSCALL msg=audit(123): test log\n")
	if err != nil {
		t.Fatal(err)
	}

	select {
	case line := <-engine.NextLine():
		expected := "type=SYSCALL msg=audit(123): test log"
		if line != expected {
			t.Fatalf("expected %q, got %q", expected, line)
		}

	case err := <-engine.Errors():
		t.Fatalf("unexpected error: %v", err)

	case <-time.After(2 * time.Second):
		t.Fatal("timeout: 로그 라인을 받지 못함")
	}
}