package main

import (
	"fmt"
	"mini_edr/collector"
	"os"
	"os/signal"
	"syscall"
)

func main() {

	fmt.Println("=========================================")
	fmt.Println("   mini-edr Collector 테스트")
	fmt.Println("=========================================")

	// ---------------------------------------------------------
	// 1. TailEngine 생성
	// ---------------------------------------------------------
	tailEngine := collector.NewTailEngine("/var/log/audit/audit.log")

	// ---------------------------------------------------------
	// 2. audit.log 실시간 추적 시작
	// ---------------------------------------------------------
	if err := tailEngine.Start(); err != nil {
		fmt.Printf("TailEngine 시작 실패 : %v\n", err)
		return
	}

	// ---------------------------------------------------------
	// 3. Audit Collector 생성
	// ---------------------------------------------------------
	auditCollector := collector.NewAuditdCollector(tailEngine)

	// ---------------------------------------------------------
	// 4. Audit Collector 시작
	// ---------------------------------------------------------
	if err := auditCollector.Start(); err != nil {
		fmt.Printf("Collector 시작 실패 : %v\n", err)
		return
	}

	// ---------------------------------------------------------
	// 5. 조립 완료된 AuditLogGroup 출력
	// ---------------------------------------------------------
	go func() {

		for group := range auditCollector.ReadyGroups() {

			fmt.Println()
			fmt.Println("===================================")
			fmt.Println("      Audit Event Complete")
			fmt.Println("===================================")

			fmt.Printf("%+v\n", group)

			fmt.Println("-----------------------------------")

			fmt.Println("AuditID :", group.ID)
			fmt.Println("Key     :", group.Key)

			if group.Syscall != nil {
				fmt.Println()
				fmt.Println("[SYSCALL]")
				fmt.Println("PID     :", group.Syscall.PID)
				fmt.Println("PPID    :", group.Syscall.PPID)
				fmt.Println("UID     :", group.Syscall.UID)
				fmt.Println("Command :", group.Syscall.Command)
				fmt.Println("Exe     :", group.Syscall.Exe)
			}

			if group.Execve != nil {
				fmt.Println()
				fmt.Println("[EXECVE]")
				fmt.Println("Argc :", group.Execve.Argc)
				fmt.Println("Args :", group.Execve.Args)
			}

			if group.Cwd != nil {
				fmt.Println()
				fmt.Println("[CWD]")
				fmt.Println("Directory :", group.Cwd.Directory)
			}

			if len(group.Paths) > 0 {
				fmt.Println()
				fmt.Println("[PATH]")

				for _, path := range group.Paths {
					fmt.Println("----------------------------")
					fmt.Println("Name     :", path.Name)
					fmt.Println("Item     :", path.Item)
					fmt.Println("NameType :", path.NameType)
				}
			}

			if group.ProcTitle != nil {
				fmt.Println()
				fmt.Println("[PROCTITLE]")
				fmt.Println("Title :", group.ProcTitle.Title)
			}

			if group.SockAddr != nil {
				fmt.Println()
				fmt.Println("[SOCKADDR]")
				fmt.Println("Address :", group.SockAddr.Address)
			}

			fmt.Println("===================================")
			fmt.Println()

		}

	}()

	// ---------------------------------------------------------
	// 6. 종료 시그널 대기
	// ---------------------------------------------------------
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	fmt.Println("Collector 실행 중...")
	fmt.Println("명령어를 실행해보세요. (ls, cat, ping 등)")
	fmt.Println("종료 : Ctrl + C")

	<-sigChan

	// ---------------------------------------------------------
	// 7. Collector 종료
	// ---------------------------------------------------------
	fmt.Println()
	fmt.Println("Collector 종료 중...")

	auditCollector.Stop()

	// ---------------------------------------------------------
	// 8. TailEngine 종료
	// ---------------------------------------------------------
	tailEngine.Stop()

	fmt.Println("모든 Collector 종료 완료")
	fmt.Println("=========================================")

}