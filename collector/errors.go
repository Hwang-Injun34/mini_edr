package collector

import (
	"fmt"
	"errors"
)

type PipelineStage string

const (
	StageTail    PipelineStage = "1단계: 실시간 Tail 수집"
	StageAssemble PipelineStage = "2단계: 인메모리 파편 조립"
)

// errors.Is 검사용
var (
	ErrLogFileMissing  = errors.New("audit.log 파일을 찾을 수 없습니다")
	ErrPermission      = errors.New("로그 파일 접근 권한(root)이 없습니다")
	ErrBufferOverflow  = errors.New("수집 채널 버퍼 용량이 한계치를 초과했습니다")
	ErrInvalidFragment = errors.New("잘못되거나 오염된 레코드 파편이 들어왔습니다")
	ErrMissingRequired = errors.New("필수 레코드가 누락되어 조립을 완료할 수 없습니다")
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