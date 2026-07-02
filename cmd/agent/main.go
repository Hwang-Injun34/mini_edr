package main

import (
	"errors"
	"fmt"
	"mini_edr/collector"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	fmt.Println("=========================================")
	fmt.Println("   mini-edr Collector 및 에러 텔레메트리 테스트")
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
	// [★ 추가] 5. 비동기 에러 통합 모니터링 루프 가동
	// ---------------------------------------------------------
	// 1단계(Tail)와 2단계(조립)의 백그라운드 에러 채널을 관측하는 통합 감시 고루틴입니다.
	go func() {
		for {
			select {
			// 1단계 엔진의 에러 수신
			case err, ok := <-tailEngine.Errors():
				if !ok {
					return
				}
				handlePipelineError(err)

			// 2단계 조립기의 에러 수신
			case err, ok := <-auditCollector.Errors():
				if !ok {
					return
				}
				handlePipelineError(err)
			}
		}
	}()

	// ---------------------------------------------------------
	// 6. 조립 완료된 AuditLogGroup 출력 (정상 흐름)
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
	// 7. 종료 시그널 대기
	// ---------------------------------------------------------
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	fmt.Println("Collector 실행 중...")
	fmt.Println("명령어를 실행해보세요. (ls, cat, ping 등)")
	fmt.Println("종료 : Ctrl + C")

	<-sigChan

	// ---------------------------------------------------------
	// 8. Collector 및 TailEngine 순차 종료
	// ---------------------------------------------------------
	fmt.Println()
	fmt.Println("Collector 종료 중...")
	auditCollector.Stop()
	tailEngine.Stop()

	fmt.Println("모든 Collector 종료 완료")
	fmt.Println("=========================================")
}

// --------------------------------------------------------------------
// [★ 추가] errors.Is 및 errors.As를 활용한 에러 정밀 분석 핸들러
// --------------------------------------------------------------------
func handlePipelineError(err error) {
	fmt.Println("\n [EDR Telemetry Alert] 내부 오작동 감지")

	// 1. errors.Is를 통한 "원인(본질)" 판별 기법 가동
	if errors.Is(err, collector.ErrPermission) {
		fmt.Println("[해결방안] 권한 부족! 에이전트를 반드시 'sudo' 권한으로 기동하세요.")
	} else if errors.Is(err, collector.ErrLogFileMissing) {
		fmt.Println("[해결방안] 리눅스 auditd 서비스가 활성화되어 있는지 확인하세요.")
	} else if errors.Is(err, collector.ErrBufferOverflow) {
		fmt.Println("[위험] 현재 하행 파이프라인 병목으로 자원 유실 위기입니다.")
	}

	// 2. errors.As를 통한 "컨텍스트 데이터(구조체)" 강제 적출
	var edrErr *collector.EDRError
	if errors.As(err, &edrErr) {
		fmt.Printf("├─ 발생 단계: %s\n", edrErr.Stage)
		fmt.Printf("├─ 오작동 컴포넌트: %s\n", edrErr.Component)
		fmt.Printf("└─ 디버깅 상세노트: %s\n", edrErr.Detail)
	} else {
		fmt.Printf("└─ 알 수 없는 시스템 오류: %v\n", err)
	}
	fmt.Println()
}