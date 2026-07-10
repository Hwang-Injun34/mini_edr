package dispatcher

import (
	"mini_edr/collector"
	"mini_edr/model"
	"sync"
	"context"
	"fmt"
)

type AlertDispatcher struct {
	inputChan   <-chan *model.SystemEvent // 4단계 룰 엔진으로부터 경보를 받는 통로
	responseOut chan *model.SystemEvent   // 5단계 대응 엔진(Response)으로 보낼 통로
	storageOut  chan *model.SystemEvent   // 6단계 저장 엔진(Storage)으로 보낼 통로
	errChan     chan error                // 비동기 에러 텔레메트리 채널
}


// NewAlertDispatcher는 AlertDispatcher 객체를 생성하고 내부 버퍼 채널들을 빌드한다. 
func NewAlertDispatcher(inputChan <-chan *model.SystemEvent) *AlertDispatcher{
	return &AlertDispatcher{
		inputChan:   inputChan,
		responseOut: make(chan *model.SystemEvent, 500), // 대응 채널
		storageOut:  make(chan *model.SystemEvent, 1000), // 저장 채널
		errChan:     make(chan error, 50),
	}
}

// ResponseChannel은 대응 레이어가 구독할 수 있도록 수신 전용 통로를 개방
func (ad *AlertDispatcher) ResponseChannel() <-chan *model.SystemEvent {
	return ad.responseOut
}


// StorageChannel은 저장/전송(Storage) 레이어가 구독할 수 있도록 수신 전용 통로를 개방
func (ad *AlertDispatcher) StorageChannel() <-chan *model.SystemEvent{
	return ad.storageOut
}

// Errors는 분배 과정 중 발생한 특이 사항을 main.go 제어판에서 관측할 수 있도록 제공
func (ad *AlertDispatcher) Errors() <- chan error{
	return ad.errChan
}

func (ad *AlertDispatcher) Start(ctx context.Context, wg *sync.WaitGroup){
	defer wg.Done()

	for{
		select {
		case <- ctx.Done():
			close(ad.responseOut)
			close(ad.storageOut)
			close(ad.errChan)
			return 

		case alert, ok := <-ad.inputChan:
			if !ok{
				return 
			}

			// 1. 메모리 데이터 오염 방지 및 동시성 격리를 위해 깊은 복사(Deep Copy)에 준하는 복제본 생성
			// 두 레이어(Response, Storage)가 같은 메모리 포인터를 쥐고 수정하다가 레이스 컨디션이 터지는 것을 원천 차단합니다.
			responseAlert := *alert
			storageAlert := *alert

			// 2. 대응 엔진(Response) 측으로 팬아웃 토스
			select {
			case ad.responseOut <- &responseAlert:
			default:
				// ad.reportError(collector.StageParse, "AlertDispatcher.Response", collector.ErrBufferOverflow, "대응 엔진 버퍼 포화로 위협 차단 이벤트 지연 위기")
			}

			// 3. 저장 엔진(Storage) 측으로 팬아웃 토스
			select {
			case ad.storageOut <- &storageAlert:
			default:
				// ad.reportError(collector.StageParse, "AlertDispatcher.Storage", collector.ErrBufferOverflow, "저장소 엔진 버퍼 포화로 로그 유실 위험")
			}
		}
	}
}


// reportError는 비동기 에러를 메인 제어판으로 리포트하는 내부 유틸리티입니다.
func (ad *AlertDispatcher) reportError(stage collector.PipelineStage, comp string, err error, detail string) {
	select {
	case ad.errChan <- &collector.EDRError{Stage: stage, Component: comp, Err: err, Detail: detail}:
	default:
		fmt.Printf("[Alert Dispatcher Overload] %s -> %s 에러 드롭\n", stage, comp)
	}
}