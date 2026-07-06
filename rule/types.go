package rule

// RuleConfig는 각각의 JSON 규칙 파일 구조를 완전히 대변하는 최상위 객체
type RuleConfig struct {
	Groups map[string]interface{} `json:"groups"` 
	Rules  []RuleDefinition       `json:"rules"`
}

// RuleDefinition은 mini-edr 룰 엔진의 개별 탐지 시그니처 명세서
type RuleDefinition struct {
	RuleID      string                 `json:"rule_id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	EventType   string                 `json:"event_type"`
	Syscall     interface{}            `json:"syscall"` // 단일 문자열 또는 문자열 배열(["execve", "execveat"]) 모두 수용
	Conditions  map[string]interface{} `json:"conditions"` // 조건의 가변 필드명(exe, ppid_exe, argv, path 등) 동적 처리
}