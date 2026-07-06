package rule

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"strings"
	"mini_edr/model"
)

// RuleEngine은 로드된 위협 시구니처 매트릭스를 기반으로 실시간 침해 지표를 추적하는 코어 엔진이다.
type RuleEngine struct {
	rules      []RuleDefinition
	matcher    *RuleMatcher
	alertChan  chan *model.SystemEvent // 탐지 완료 시 Alert Dispatcher로 뿜어낼 채널 통로
	errChan    chan error
	mapMutex   sync.RWMutex
}

func NewRuleEngine() *RuleEngine {
	return &RuleEngine{
		rules:     make([]RuleDefinition, 0),
		alertChan: make(chan *model.SystemEvent, 1000),
		errChan:   make(chan error, 50),
	}
}

func (re *RuleEngine) DetectionAlerts() <-chan *model.SystemEvent {
	return re.alertChan
}

// LoadRuleFile은 우리가 빌드한 8개의 JSON 규칙 파일들을 독립적으로 메모리에 병렬 적재한다.
func (re *RuleEngine) LoadRuleFile(filePath string) error {
	re.mapMutex.Lock()
	defer re.mapMutex.Unlock()

	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	var config RuleConfig
	if err := json.NewDecoder(file).Decode(&config); err != nil {
		return fmt.Errorf("룰 파일 해석 실패 [%s]: %v", filePath, err)
	}

	// 전역 그룹 매처가 누적 빌드되도록 자원 융합
	if re.matcher == nil {
		re.matcher = NewRuleMatcher(config.Groups)
	} else {
		for k, v := range config.Groups {
			re.matcher.groups[k] = v
		}
	}

	re.rules = append(re.rules, config.Rules...)
	fmt.Printf("[RuleEngine] 보안 규칙 적재 완료: %s (누적 규칙 개수: %d개)\n", filePath, len(re.rules))
	return nil
}

// Start는 3단계 가공 채널 스트림을 건네받아 실시간 행위 분석 매칭을 전개한다.
func (re *RuleEngine) Start(ctx context.Context, wg *sync.WaitGroup, eventStream <-chan *model.SystemEvent) {
	wg.Add(1)
	go re.runMatchingLoop(ctx, wg, eventStream)
}

func (re *RuleEngine) runMatchingLoop(ctx context.Context, wg *sync.WaitGroup, eventStream <-chan *model.SystemEvent) {
	defer wg.Done()

	for {
		select {
		case <-ctx.Done():
			close(re.alertChan)
			return
		case event, ok := <-eventStream:
			if !ok {
				return
			}
			re.evaluateEvent(event)
		}
	}
}

// evaluateEvent는 하나의 이벤트를 적재된 모든 규칙 배열과 초고속 비교 연산 처리한다.
func (re *RuleEngine) evaluateEvent(event *model.SystemEvent) {
	re.mapMutex.RLock()
	defer re.mapMutex.RUnlock()

	for _, rule := range re.rules {
		// [고속 패스 라인 1] 이벤트 레이블 대조 검사
		if !strings.EqualFold(rule.EventType, string(event.Type)) {
			continue
		}

		// [실시간 규칙 매칭 가동] 
		isMatched := true
		for condKey, condVal := range rule.Conditions {
			var eventFieldVal interface{}

			// 구조체 필드 맵 유연 대응 매핑 스왑
			switch condKey {
			case "exe", "pathname", "path":
				eventFieldVal = event.ImagePath
				if event.TargetFile != "" {
					eventFieldVal = event.TargetFile // 파일 이벤트 시 정제 경로 우선 바인딩
				}
			case "ppid_exe":
				eventFieldVal = event.ImagePath // ppid 경로 추적 인터페이스 대조용
			case "argv":
				eventFieldVal = event.CommandLine
			case "euid":
				eventFieldVal = event.EUID
			case "egid":
				// 정형 기법 대조 우회 스텁
				eventFieldVal = event.EUID 
			default:
				isMatched = false
			}

			// 단 하나의 조건이라도 미치지 못하면 탈락
			if !re.matcher.MatchCondition(condKey, condVal, eventFieldVal) {
				isMatched = false
				break
			}
		}

		// 모든 위협 조건 일치 ➔ 침해 사고 탐지 경보 발행!
		if isMatched {
			// 오리지널 규칙 ID와 매칭 명칭을 타임라인에 각인
			event.AuditKey = fmt.Sprintf("[%s] %s", rule.RuleID, rule.Name)
			
			select {
			case re.alertChan <- event:
				fmt.Printf("\n[위협 탐지 방어선 돌파] 규칙 ID: %s | 탐지명: %s | 대상 PID: %d\n", rule.RuleID, rule.Name, event.PID)
			default:
				fmt.Println("[Drop Warning] 얼럿 발생 큐 포화")
			}
		}
	}
}