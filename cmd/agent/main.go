package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"

	"mini_edr/collector"
	"mini_edr/dispatcher"
	"mini_edr/rule"
)

func main() {
	fmt.Println("==================================================")
	fmt.Println("        mini-edr Rule Engine 테스트 모드")
	fmt.Println("==================================================")

	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())

	tailEngine := collector.NewTailEngine("/var/log/audit/audit.log")
	if err := tailEngine.Start(); err != nil {
		fmt.Printf("[Err] TailEngine 시작 실패: %v\n", err)
		return
	}

	auditCollector := collector.NewAuditdCollector(tailEngine)
	if err := auditCollector.Start(); err != nil {
		fmt.Printf("[Err] AuditdCollector 시작 실패: %v\n", err)
		return
	}

	eventDispatcher := dispatcher.NewEventDispatcher(
		auditCollector.ReadyGroups(),
	)
	eventDispatcher.Start(ctx, &wg)

	ruleEngine := rule.NewRuleEngine()

	_, currentFile, _, _ := runtime.Caller(0)
	projectRoot := filepath.Dir(
		filepath.Dir(
			filepath.Dir(currentFile),
		),
	)
	rulesDir := filepath.Join(projectRoot, "rules")

	ruleFiles := []string{
		filepath.Join(rulesDir, "processCreation.json"),
		filepath.Join(rulesDir, "fileCreation.json"),
		filepath.Join(rulesDir, "fileDeletetion.json"),
		filepath.Join(rulesDir, "networkConnection.json"),
		filepath.Join(rulesDir, "privilegeEscalation.json"),
		filepath.Join(rulesDir, "processAccess.json"),
		filepath.Join(rulesDir, "persistenceRule_1.json"),
		filepath.Join(rulesDir, "persistenceRule_2.json"),
	}

	for _, file := range ruleFiles {
		if err := ruleEngine.LoadRuleFile(file); err != nil {
			fmt.Printf(
				"[Rule Load Err] %s: %v\n",
				filepath.Base(file),
				err,
			)
		}
	}

	ruleEngine.Start(
		ctx,
		&wg,
		eventDispatcher.ParsedEvents(),
	)

	// 탐지 성공 이벤트 출력
	go func() {
		for alert := range ruleEngine.DetectionAlerts() {
			fmt.Println()
			fmt.Println("==================================================")
			fmt.Println("[ALERT] RuleEngine 탐지 성공")
			fmt.Println("==================================================")

			// --------------------------------
			// Rule 및 이벤트 메타 정보
			// --------------------------------
			fmt.Printf("├─ Rule: %s\n", alert.AuditKey)
			fmt.Printf("├─ Type: %s\n", alert.Type)
			fmt.Printf("├─ Event ID: %d\n", alert.ID)
			fmt.Printf("├─ Event Time: %s\n", alert.Time)

			// --------------------------------
			// 시스템 콜 정보
			// --------------------------------
			fmt.Printf("├─ SyscallName: %s\n", alert.SyscallName)
			fmt.Printf("├─ Success: %t\n", alert.Success)
			fmt.Printf("├─ Exit: %d\n", alert.Exit)

			// --------------------------------
			// 프로세스 정보
			// --------------------------------
			fmt.Printf("├─ PID/PPID: %d/%d\n", alert.PID, alert.PPID)
			fmt.Printf("├─ UID/EUID: %d/%d\n", alert.UID, alert.EUID)
			fmt.Printf("├─ GID/EGID: %d/%d\n", alert.GID, alert.EGID)
			fmt.Printf("├─ ProcessName: %s\n", alert.ProcessName)
			fmt.Printf("├─ Image: %s\n", alert.ImagePath)
			fmt.Printf("├─ ParentImage: %s\n", alert.ParentImage)

			// --------------------------------
			// 명령 실행 정보
			// --------------------------------
			fmt.Printf("├─ CommandLine: %s\n", alert.CommandLine)
			fmt.Printf("├─ CurrentDir: %s\n", alert.CurrentDir)

			// --------------------------------
			// 파일 이벤트 정보
			// --------------------------------
			fmt.Printf("├─ TargetFile: %s\n", alert.TargetFile)
			fmt.Printf("├─ PathName: %s\n", alert.PathName)
			fmt.Printf("├─ FileExt: %s\n", alert.FileExt)

			// --------------------------------
			// ProcessAccess 정보
			// --------------------------------
			fmt.Printf("├─ Request: %s\n", alert.Request)
			fmt.Printf("├─ TargetPID: %d\n", alert.TargetPID)

			// --------------------------------
			// 네트워크 정보
			// --------------------------------
			fmt.Printf("├─ DstIP: %s\n", alert.DstIP)
			fmt.Printf("├─ DstPort: %d\n", alert.DstPort)
			fmt.Printf("└─ Protocol: %s\n", alert.Protocol)

			fmt.Println("==================================================")
		}
	}()

	// 파이프라인 에러 출력
	go func() {
		for {
			select {
			case err := <-tailEngine.Errors():
				if err != nil {
					fmt.Printf("[Err] TailEngine: %v\n", err)
				}

			case err := <-auditCollector.Errors():
				if err != nil {
					fmt.Printf("[Err] AuditdCollector: %v\n", err)
				}

			case err := <-eventDispatcher.Errors():
				if err != nil {
					fmt.Printf("[Err] EventDispatcher: %v\n", err)
				}

			case <-ctx.Done():
				return
			}
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(
		sigChan,
		syscall.SIGINT,
		syscall.SIGTERM,
	)

	fmt.Println()
	fmt.Println("-> Rule Engine까지 테스트 중... 종료하려면 Ctrl+C")

	<-sigChan

	fmt.Println()
	fmt.Println("-> 테스트 종료 중...")

	cancel()
	auditCollector.Stop()
	tailEngine.Stop()
	wg.Wait()

	fmt.Println("==================================================")
	fmt.Println("        테스트 종료 완료")
	fmt.Println("==================================================")
}