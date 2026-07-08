package collector

import "testing"

func TestParseSockAddrRecord(t *testing.T) {
	c := NewAuditdCollector(nil)

	line := `type=SOCKADDR msg=audit(1783506680.127:46388): saddr=020000508EFB77640000000000000000SADDR={ saddr_fam=inet laddr=142.251.119.100 lport=80 }`

	record := c.parseSockAddrRecord(line)

	if record.RawAddress != "020000508EFB77640000000000000000" {
		t.Fatalf("RawAddress mismatch: %s", record.RawAddress)
	}
	if record.Family != "inet" {
		t.Fatalf("Family mismatch: %s", record.Family)
	}
	if record.IP != "142.251.119.100" {
		t.Fatalf("IP mismatch: %s", record.IP)
	}
	if record.Port != 80 {
		t.Fatalf("Port mismatch: %d", record.Port)
	}
}

func TestProcessLineNetworkConnectMapping(t *testing.T) {
	c := NewAuditdCollector(nil)

	lines := []string{
		`type=SYSCALL msg=audit(1783506680.127:46388): arch=c000003e syscall=42 success=yes exit=0 a0=3 a1=7ffc a2=16 items=0 ppid=1666 pid=20453 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=3 comm="curl" exe="/usr/bin/curl" subj=unconfined key="network_connect" ARCH=x86_64 SYSCALL=connect`,
		`type=SOCKADDR msg=audit(1783506680.127:46388): saddr=020000508EFB77640000000000000000SADDR={ saddr_fam=inet laddr=142.251.119.100 lport=80 }`,
		`type=CWD msg=audit(1783506680.127:46388): cwd="/home/pumpkinbee/mini_edr"`,
		`type=PATH msg=audit(1783506680.127:46388): item=0 name="/usr/bin/curl" inode=4981511 dev=fd:00 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0 OUID="root" OGID="root"`,
	}

	for _, line := range lines {
		c.processLine(line)
	}

	select {
	case group := <-c.ReadyGroups():
		if group.Key != "network_connect" {
			t.Fatalf("Key mismatch: %s", group.Key)
		}
		if group.Syscall == nil {
			t.Fatal("SyscallRecord is nil")
		}
		if group.Syscall.Command != "curl" {
			t.Fatalf("Command mismatch: %s", group.Syscall.Command)
		}
		if group.Syscall.SyscallName != "connect" {
			t.Fatalf("SyscallName mismatch: %s", group.Syscall.SyscallName)
		}
		if group.SockAddr == nil {
			t.Fatal("SockAddrRecord is nil")
		}
		if group.SockAddr.IP != "142.251.119.100" {
			t.Fatalf("SockAddr IP mismatch: %s", group.SockAddr.IP)
		}
		if group.SockAddr.Port != 80 {
			t.Fatalf("SockAddr Port mismatch: %d", group.SockAddr.Port)
		}
		if group.Cwd == nil || group.Cwd.Directory != "/home/pumpkinbee/mini_edr" {
			t.Fatalf("CWD mismatch")
		}
		if len(group.Paths) != 1 {
			t.Fatalf("PATH count mismatch: %d", len(group.Paths))
		}
		if group.Paths[0].Name != "/usr/bin/curl" {
			t.Fatalf("PATH name mismatch: %s", group.Paths[0].Name)
		}

	default:
		t.Fatal("조립 완료된 NetworkConnect 이벤트가 ReadyGroups로 전달되지 않았습니다")
	}
}