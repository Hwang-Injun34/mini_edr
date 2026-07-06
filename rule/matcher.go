package rule

import (
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
)

type RuleMatcher struct {
	groups map[string]interface{}
}

func NewRuleMatcher(groups map[string]interface{}) *RuleMatcher {
	return &RuleMatcher{groups: groups}
}

// MatchCondition은 이벤트의 특정 필드 값과 조건에 명시된 그룹(또는 값)이 일치하는지 정밀 판독한다.
func (m *RuleMatcher) MatchCondition(condKey string, condValue interface{}, eventVal interface{}) bool {
	if condValue == nil || eventVal == nil {
		return false
	}

	// 규칙에 선언된 조건이 그룹명을 가리키는 문자열인 경우 (예: "exe": "Shell")
	if strGroup, ok := condValue.(string); ok {
		if groupItems, exists := m.groups[strGroup]; exists {
			return m.checkValueInGroup(groupItems, eventVal)
		}
		// 그룹명이 아니라 직접 대조용 일반 문자열인 경우
		return m.compareValue(strGroup, eventVal)
	}

	// 규칙에 선언된 조건이 복수 그룹인 경우 (예: "ppid_exe": ["WebServer", "RemoteSession"])
	if sliceCond, ok := condValue.([]interface{}); ok {
		for _, item := range sliceCond {
			if strItem, ok := item.(string); ok {
				if groupItems, exists := m.groups[strItem]; exists {
					if m.checkValueInGroup(groupItems, eventVal) {
						return true
					}
				}
				if m.compareValue(strItem, eventVal) {
					return true
				}
			}
		}
		return false
	}

	// 하위 옵션 구조체 대조 (예: processCreation의 argv 맵 탐색)
	if mapCond, ok := condValue.(map[string]interface{}); ok {
		if strEvent, ok := eventVal.(string); ok {
			for _, targetGroup := range mapCond {
				if strGrp, ok := targetGroup.(string); ok {
					if grpItems, exists := m.groups[strGrp]; exists {
						if m.checkValueInGroup(grpItems, strEvent) {
							return true
						}
					}
				}
			}
		}
	}

	return false
}

// checkValueInGroup은 자원 그룹 풀(Slice/Map) 내부에 해당 이벤트 컨텍스트가 속해 있는지 검사한다.
func (m *RuleMatcher) checkValueInGroup(group interface{}, eventVal interface{}) bool {
	v := reflect.ValueOf(group)
	if v.Kind() == reflect.Slice {
		for i := 0; i < v.Len(); i++ {
			item := v.Index(i).Interface()
			if m.compareValue(item, eventVal) {
				return true
			}
		}
	}
	
	// 혼합 오브젝트 맵 형태 방어 (예: Download.command 배열 처리)
	if v.Kind() == reflect.Map {
		for _, key := range v.MapKeys() {
			subGroup := v.MapIndex(key).Interface()
			if m.checkValueInGroup(subGroup, eventVal) {
				return true
			}
		}
	}
	return false
}

// compareValue는 파일 와일드카드(*), 정수 대조, 대소문자 부분 검색을 수행한다.
func (m *RuleMatcher) compareValue(ruleVal interface{}, eventVal interface{}) bool {
	// 1. 와일드카드 패턴 매칭 기법 작동 (예: /etc/systemd/system/*.service)
	if rStr, ok := ruleVal.(string); ok {
		if eStr, ok := eventVal.(string); ok {
			// 와일드카드 문자(*)를 포함하고 있다면 표준 filepath.Match 가동
			if strings.Contains(rStr, "*") {
				matched, _ := filepath.Match(rStr, eStr)
				if matched {
					return true
				}
			}
			// 명령어 인자 부분 포함 검색 연계 (예: argv에 POST가 포함되어 있는지 대조)
			return strings.Contains(strings.ToLower(eStr), strings.ToLower(rStr))
		}
	}

	// 2. UID/EUID/포트 정수형 대조 방어선 (예: RootUser == 0)
	if rNum, ok := m.toInt64(ruleVal); ok {
		if eNum, ok := m.toInt64(eventVal); ok {
			return rNum == eNum
		}
	}

	return false
}

func (m *RuleMatcher) toInt64(val interface{}) (int64, bool) {
	switch v := val.(type) {
	case int:    return int64(v), true
	case int64:   return v, true
	case float64: return int64(v), true
	case string:
		n, err := strconv.ParseInt(v, 10, 64)
		if err == nil { return n, true }
	}
	return 0, false
}