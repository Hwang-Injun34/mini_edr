package model

import (
	"time"
	"mini_edr/collector"
)


// ====================================================================
// SystemEvent 구조체 (Rule Engine 및 대시보드로 넘어갈 최종 완제품)
// ====================================================================
type SystemEvent struct {
	ID        uint64    `json:"id"`        // 비동기 파이프라인 정렬용 고유 시퀀스 번호
	Time      time.Time `json:"time"`      // 이벤트 생성/탐지 타임스탬프
	Type      collector.EventType `json:"type"`      // 최종 결론 레이블
	AuditKey  string    `json:"audit_key"` // Auditd 규칙의 -k 태그 값
	PID       int       `json:"pid"`
	PPID      int       `json:"ppid"`
	UID       int       `json:"uid"`
	EUID      int       `json:"euid"`

	ProcessName string `json:"process_name"`
	ImagePath   string `json:"image_path"`
	CommandLine string `json:"command_line"`

	TargetFile string `json:"target_file"` // 파일 이벤트용 타깃 명시

	// 저사양 PC 최화: 원시 스트링 보관으로 가비지 컬렉터(GC) 부하 차단
	RawMessage string `json:"-"` 
}