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
	fmt.Println("        mini-edr 실시간 침해 사고 대응 엔진 가동")
	fmt.Println("==================================================")

	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())

	// 1. 인프라 레이어 셋업 (1, 2단계 수집기)
	tailEngine := collector.NewTailEngine("/var/log/audit/audit.log")
	_ = tailEngine.Start()
	auditCollector := collector.NewAuditdCollector(tailEngine)
	_ = auditCollector.Start()

	// 2. 가공 레이어 셋업 (3단계 디스패처)
	eventDispatcher := dispatcher.NewEventDispatcher(auditCollector.ReadyGroups())
	eventDispatcher.Start(ctx, &wg)

	// 3. 분석 레이어 셋업 및 8대 규칙 로드 (4단계 룰 엔진)
	ruleEngine := rule.NewRuleEngine()
	
	// 실행 중인 main.go 파일의 물리적 절대 경로를 런타임 추적
	_, currentFile, _, _ := runtime.Caller(0)
	// cmd/agent/main.go 에서 두 단계 위로 올라가 프로젝트 루트 경로 확보
	projectRoot := filepath.Dir(filepath.Dir(filepath.Dir(currentFile)))
	rulesDir := filepath.Join(projectRoot, "rules")

	// 컴파일 타임 샌드박스 경로 확인 로그
	fmt.Printf("[System] 동적 감지된 규칙 저장소 절대 경로: %s\n", rulesDir)

	// 동적으로 추출된 룰 디렉터리 경로를 기반으로 파일 목록 매핑
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
			fmt.Printf("룰 파일 적재 누수 발생 [%s]: %v\n", filepath.Base(file), err)
		}
	}

	// 4. 파이프라인 결합: [3단계 배출구] ──> [4단계 룰 엔진 입력구] 도킹!
	ruleEngine.Start(ctx, &wg, eventDispatcher.ParsedEvents())

	// 5. 위협 얼럿 출력 고루틴 백그라운드 구동
	go func() {
		for alertEvent := range ruleEngine.DetectionAlerts() {
			fmt.Println("\n==================================================")
			fmt.Printf(" 침해 지표 실시간 탐지 레이더 알림\n")
			fmt.Printf("├─ 탐지 시그니처: %s\n", alertEvent.AuditKey)
			fmt.Printf("├─ 침해 원인 프로세스: %s (PID: %d)\n", alertEvent.ProcessName, alertEvent.PID)
			fmt.Printf("├─ 악성 공격 명령행: %s\n", alertEvent.CommandLine)
			fmt.Printf("└─ 탐지 매칭 자원 타깃: %s\n", alertEvent.TargetFile)
			fmt.Println("==================================================")
		}
	}()

	// 6. 비동기 오류 알림 제어판 도킹 (기존 로직 동일)
	go func() {
		for {
			select {
			case err := <-tailEngine.Errors():      if err != nil { fmt.Printf("[Err] %v\n", err) }
			case err := <-auditCollector.Errors():  if err != nil { fmt.Printf("[Err] %v\n", err) }
			case err := <-eventDispatcher.Errors(): if err != nil { fmt.Printf("[Err] %v\n", err) }
			case <-ctx.Done(): return
			}
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	fmt.Println("\n-> 에이전트 분석 파이프라인 완공 완료. 실시간 방어 중...")
	<-sigChan

	// 7. 자원 역순 해제 및 클렌징 종료
	fmt.Println("\n-> 보안 에이전트 셧다운 절차를 개시합니다...")
	cancel()
	auditCollector.Stop()
	tailEngine.Stop()
	wg.Wait()
	fmt.Println("==================================================")
	fmt.Println("        mini-edr 에이전트가 안전하게 종료되었습니다.")
	fmt.Println("==================================================")
}