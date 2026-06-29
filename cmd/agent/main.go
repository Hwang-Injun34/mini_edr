package main

import (
	"fmt"
	"mini_edr/collector"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main(){
	fmt.Println("=========================================")
	fmt.Println("	mini-edr 경량 보안 에이전트 구동(1단계)   ") 
	fmt.Println("=========================================")

	// [1] 추적을 위한 경로 인자로 함수 실행
	tailEngine := collector.NewTailEngine("/var/log/audit/audit.log")

	// [2] tailEngine 실행
	if err := tailEngine.Start(); err != nil {
		fmt.Printf("에이전트 초기화 실패: %v\n", err)
		return 
	}

	// [3] 실시간으로 떨어지는 라인을 화면에 바인딩하는 임시 모니터링 고루틴 작동
	go func(){
		for line := range tailEngine.NextLine() {
			fmt.Printf("[Raw Line 캡쳐] %s\n", line)
		}
	}()

	// [4] Linux 표준 종료 시그널(Ctrl + C, kill) 감지용 가드 배치
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	fmt.Println("-> 에이전트 실시간 동작 중... 종료 시 Ctrl + C")
	<- sigChan

	// [5] 종료 시 수거
	fmt.Println("\n -> 에이전트 명령 감지")
	tailEngine.Stop()

	time.Sleep(500 * time.Millisecond)
	fmt.Println("=========================================")
	fmt.Println("	mini-edr 경량 보안 에이전트 종료(1단계)   ") 
	fmt.Println("=========================================")
}