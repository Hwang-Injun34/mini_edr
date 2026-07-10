package dispatcher

import (
	"fmt"
	"errors"
)

type PipelineStage string

const (
	   StageTransform PipelineStage = "3단계: 이벤트 변환"
)

// errors.Is 검사용
var (
	ErrUnsupporttedEvent = errors.New("지원하지 않는 이벤트 타입입니다.")
	ErrBufferOverflow = errors.New("출력 채널 버퍼 용량 초과")
	ErrMappingFailed = errors.New("이벤트 매핑 실패")
)

// EDRError: 구체적인 컨텍스트를 담을 커스텀 에러 구조체
type EDRError struct {
	Stage     PipelineStage // 어느 단계인가 (1단계, 2단계)
	Component string        // 어느 함수/컴포넌트인가 (ex: "runTailLoop", "processLine")
	Err       error         // 어떤 원인인가 (위의 센티넬 에러 또는 외부 라이브러리 에러)
	Detail    string        // 구체적인 커스텀 설명
}

// Error: Go 표준 error 인터페이스 만족을 위한 포맷팅 출력 함수
func (e *EDRError) Error() string {
	return fmt.Sprintf("[%s -> %s] 오류 발생: %v (%s)", e.Stage, e.Component, e.Err, e.Detail)
}

// Unwrap: errors.As 및 errors.Is가 내부 에러를 파고들 수 있도록 길을 열어주는 핵심 함수
func (e *EDRError) Unwrap() error {
	return e.Err
}