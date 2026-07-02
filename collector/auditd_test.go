package collector

import (
	"testing"

)

func TestExtractAuditID(t *testing.T) {

	c := &AuditdCollector{}

	line := `type=SYSCALL msg=audit(1782650957.030:72994): arch=c000003e`

	id := c.extractAuditID(line)

	if id != "1782650957.030:72994" {
		t.Fatalf("want 1782650957.030:72994, got %s", id)
	}
}


func TestIdentifyRecordType(t *testing.T) {

	c := &AuditdCollector{}

	tests := []struct {
		line string
		want RecordType
	}{
		{
			"type=SYSCALL msg=audit(...)",
			SYSCALL,
		},
		{
			"type=EXECVE msg=audit(...)",
			EXECVE,
		},
		{
			"type=CWD msg=audit(...)",
			CWD,
		},
		{
			"type=PATH msg=audit(...)",
			PATH,
		},
		{
			"type=PROCTITLE msg=audit(...)",
			PROCTITLE,
		},
	}

	for _, tt := range tests {

		got := c.identifyRecordType(tt.line)

		if got != tt.want {
			t.Fatalf("want %v got %v", tt.want, got)
		}
	}
}

func TestParseStringField(t *testing.T) {

	c := &AuditdCollector{}

	line := `type=SYSCALL pid=1234 comm="ls" exe="/usr/bin/ls"`

	comm := c.parseStringField(line, "comm=")
	exe := c.parseStringField(line, "exe=")

	if comm != "ls" {
		t.Fatal(comm)
	}

	if exe != "/usr/bin/ls" {
		t.Fatal(exe)
	}
}

func TestParseIntField(t *testing.T) {

	c := &AuditdCollector{}

	line := `pid=2351 ppid=1715 uid=0`

	pid := c.parseIntField(line, "pid=")

	if pid != 2351 {
		t.Fatal(pid)
	}
}

func TestParseSyscallRecord(t *testing.T) {

	c := &AuditdCollector{}

	line := `type=SYSCALL success=yes exit=0 pid=2351 ppid=1715 uid=0 euid=0 gid=0 comm="ls" exe="/usr/bin/ls" tty=pts0 key="process_create"`

	record := c.parseSyscallRecord(line)

	if record == nil {
		t.Fatal("record is nil")
	}

	if record.PID != 2351 {
		t.Fatal(record.PID)
	}

	if record.Command != "ls" {
		t.Fatal(record.Command)
	}

	if record.Key != "process_create" {
		t.Fatal(record.Key)
	}
}

func TestParseExecveRecord(t *testing.T) {
	c := &AuditdCollector{}

	line := `type=EXECVE argc=2 a0="ls" a1="-al"`

	record := c.parseExecveRecord(line)

	if record == nil {
		t.Fatal("record is nil")
	}

	if record.Argc != 2 {
		t.Fatalf("expected argc=2, got %d", record.Argc)
	}

	if len(record.Args) != 2 {
		t.Fatalf("expected 2 args, got %d", len(record.Args))
	}

	if record.Args[0] != "ls" {
		t.Fatalf("expected a0=ls, got %q", record.Args[0])
	}

	if record.Args[1] != "-al" {
		t.Fatalf("expected a1=-al, got %q", record.Args[1])
	}
}

func TestIsReadyToAssemble(t *testing.T) {
	c := &AuditdCollector{}

	group := &AuditLogGroup{
		Key: "process_create",

		Syscall:   &SyscallRecord{},
		Execve:    &ExecveRecord{},
		Cwd:       &CwdRecord{},
		Paths:     []*PathRecord{{}}, // PATH 하나 존재
		ProcTitle: &ProcTitleRecord{},
	}

	if !c.isReadyToAssemble(group) {
		t.Fatal("expected group to be ready")
	}
}


func TestProcessLine(t *testing.T) {

	c := NewAuditdCollector(nil)

	lines := []string{

		`type=SYSCALL msg=audit(1:1) success=yes pid=1 key="process_create"`,

		`type=EXECVE msg=audit(1:1) argc=1 a0="ls"`,

		`type=CWD msg=audit(1:1) cwd="/home"`,

		`type=PATH msg=audit(1:1) item=0 name="/usr/bin/ls"`,

		`type=PROCTITLE msg=audit(1:1) proctitle="ls"`,
	}

	for _, line := range lines {
		c.processLine(line)
	}

	select {

	case event := <-c.ReadyGroups():

		if event == nil {
			t.Fatal("nil event")
		}

	default:

		t.Fatal("event not generated")
	}
}