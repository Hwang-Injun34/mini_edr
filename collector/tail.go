package collector

import (
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/hpcloud/tail"
)

type TailEngine struct {
	logPath string
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	lineChan chan string // 추출된 한 줄을 외부로 전달할 논블로킹 채널 통로
	errChan chan error 
}



//	NewTailEngine은 TailEngine 객체를 생성하고 초기화한다.
//	로그 파일 경로(/var/log/audit/audit.log)와 종료를 위한 Context를 생성하며,
//	로그 수집에 사용할 버퍼 채널을 함께 준비하여 반환한다.
func NewTailEngine(logPath string) *TailEngine {
	ctx, cancel := context.WithCancel(context.Background())
	return &TailEngine{
		logPath:  logPath,
		ctx:      ctx,
		cancel:   cancel,
		lineChan: make(chan string, 1000),  // 버퍼 크기 임시 지정
		errChan: make(chan error, 10),
		}
}


//	NextLine은 하부 엔진에서 한 줄씩 꺼내 갈 수 있도록 수신 채널 제공한다.
func (t *TailEngine) NextLine() <-chan string {
	return t.lineChan
}


//	Errors는 내부 에러를 전달하기 위한 에러 수신용 채널을 제공한다. 
func (t *TailEngine) Errors() <- chan error {
	return t.errChan
}


// 	Start는 TailEngine의 실시간 로그 감시를 시작한다. 
//	별도의 goroutine을 생성하여 audit.log를 감시하며, 
// 	메인 흐름을 차단하지 않고 새로운 로그를 지속적으로 수집한다. 
func (t *TailEngine) Start() error {
	t.wg.Add(1)
	go t.runLoop()
	return nil
}


// 	Stop은 TailEngine을 종료하는 함수이다.
//  안전한 종료를 위해 goroutine이 모두 종료될 때까지 대기한 후 실행되며,
//	수행 시 버퍼도 함께 종료된다. 
func (t *TailEngine) Stop() {
	t.cancel()
	t.wg.Wait()
	close(t.lineChan)
	close(t.errChan)
	fmt.Println("[TailEngine] 실시간 파일 디스크립터 및 에러 파이프라인이 안전하게 닫혔습니다.")
}


// runLoop는 github.com/hpcloud/tail을 사용하여, 로그를 수집한다. 
// 실행되면 종료되기 전까지 새로 들어오는 로그를 한 줄씩 수집하며, 
// 종료 시에는 context의 신호가 오면 종료된다. 
func (t *TailEngine) runLoop() {
	defer t.wg.Done()

	config := tail.Config{
		Follow:    true, // 실시간 로그 추적 (tail -f 동일)
		ReOpen:    true, // 로그 파일 로테이트(쪼개기) 발생 시 즉시 새 파일로 자동 링크 변경
		MustExist: true,
		// 현재 시점 기준 파일 맨 끝(Whence=2)으로 강제 점프하여 구동 시 OOM 메모리 폭발 방지
		Location:  &tail.SeekInfo{Offset: 0, Whence: 2}, 
	}

	tailStream, err := tail.TailFile(t.logPath, config)
	if err != nil {
		var wrappedErr error = ErrLogFileMissing
		if os.IsPermission(err) {
			wrappedErr = ErrPermission
		}

		select {
			case t.errChan <- &EDRError{
				Stage: StageTail, 
				Component: "runLoop.TailFile",
				Err: wrappedErr,
				Detail: fmt.Sprintf("대상 로그 경로: %s | 원본 오류: %v", t.logPath, err),
			}:
			default:
				fmt.Printf("[Crit-Error] %s 가동 실패 메일 전달 누수 발생.\n", t.logPath)
		}
		return
	}

	fmt.Printf("[TailEngine] %s 맨 마지막 라인에 성공적으로 연결되었습니다.\n", t.logPath)

	for {
		select {
		case <-t.ctx.Done(): // 에이전트 정지 신호 수신 시
			tailStream.Stop()
			return
		case line, ok := <-tailStream.Lines: // 커널에 의해 파일 끝에 '새로운 한 줄'이 적재되었을 때
			if !ok {
				return
			}
			
			select {
			case t.lineChan <- line.Text: // 낱개 문자열을 가공 없이 채널로 송신
			default:
				select {
					case t.errChan <- &EDRError{
						Stage: StageTail,
						Component: "runLoop.ChannelWrite",
						Err: ErrBufferOverflow,
						Detail: fmt.Sprintf("1단계 수집 채널 최대 제한 수량(1000) 초과 유실 위기. 원문: %.30s...", line.Text),
					}:
					default:
						fmt.Println("[Drop Warning] 원시 로그 수신 버퍼 및 에러 채널 동시 풀(Full) 상태")
						fmt.Println()
				}
			}
		}
	}
}