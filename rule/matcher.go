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

// MatchCondition은 이벤트의 특정 필드 값과 조건에 명시된 그룹 또는 값이 일치하는지 검사한다.
func (m *RuleMatcher) MatchCondition(condKey string, condValue interface{}, eventVal interface{}) bool {
	if condValue == nil || eventVal == nil {
		return false
	}

	if strCond, ok := condValue.(string); ok {
		if groupItems, exists := m.groups[strCond]; exists {
			return m.checkValueInGroup(condKey, groupItems, eventVal)
		}

		return m.compareValue(condKey, strCond, eventVal)
	}

	if sliceCond, ok := condValue.([]interface{}); ok {
		for _, item := range sliceCond {
			strItem, ok := item.(string)
			if !ok {
				continue
			}

			if groupItems, exists := m.groups[strItem]; exists {
				if m.checkValueInGroup(condKey, groupItems, eventVal) {
					return true
				}
			}

			if m.compareValue(condKey, strItem, eventVal) {
				return true
			}
		}

		return false
	}

	if mapCond, ok := condValue.(map[string]interface{}); ok {
		for _, targetGroup := range mapCond {
			strGroup, ok := targetGroup.(string)
			if !ok {
				continue
			}

			groupItems, exists := m.groups[strGroup]
			if !exists {
				continue
			}

			if m.checkValueInGroup(condKey, groupItems, eventVal) {
				return true
			}
		}
	}

	return false
}

// checkValueInGroup은 그룹 내부의 Slice 또는 Map을 재귀적으로 탐색한다.
func (m *RuleMatcher) checkValueInGroup(condKey string, group interface{}, eventVal interface{}) bool {
	v := reflect.ValueOf(group)

	if !v.IsValid() {
		return false
	}

	if v.Kind() == reflect.Slice {
		for i := 0; i < v.Len(); i++ {
			item := v.Index(i).Interface()

			if m.compareValue(condKey, item, eventVal) {
				return true
			}
		}
	}

	if v.Kind() == reflect.Map {
		for _, key := range v.MapKeys() {
			subGroup := v.MapIndex(key).Interface()

			if m.checkValueInGroup(condKey, subGroup, eventVal) {
				return true
			}
		}
	}

	return false
}

// compareValue는 조건 key에 따라 문자열, 와일드카드, 숫자를 비교한다.
func (m *RuleMatcher) compareValue(condKey string, ruleVal interface{}, eventVal interface{}) bool {
	if rStr, ok := ruleVal.(string); ok {
		if eStr, ok := eventVal.(string); ok {
			if strings.Contains(rStr, "*") {
				matched, _ := filepath.Match(rStr, eStr)
				if matched {
					return true
				}
			}

			if condKey == "argv" {
				return m.matchCommandToken(rStr, eStr)
			}

			return strings.Contains(strings.ToLower(eStr), strings.ToLower(rStr))
		}
	}

	if rNum, ok := m.toInt64(ruleVal); ok {
		if eNum, ok := m.toInt64(eventVal); ok {
			return rNum == eNum
		}
	}

	return false
}

// matchCommandToken은 CommandLine을 토큰 단위로 나누어 명령어를 비교한다.
// 예: "uname -a"는 ["uname", "-a"]로 분리되고, ruleVal이 "uname"이면 true.
// 예: "ls --color=auto"는 "ls"가 룰 그룹에 없으면 false.
func (m *RuleMatcher) matchCommandToken(ruleVal string, commandLine string) bool {
	ruleVal = strings.ToLower(filepath.Base(ruleVal))

	tokens := strings.Fields(strings.ToLower(commandLine))

	for _, token := range tokens {
		token = filepath.Base(token)

		if token == ruleVal {
			return true
		}
	}

	return false
}

func (m *RuleMatcher) toInt64(val interface{}) (int64, bool) {
	switch v := val.(type) {
	case int:
		return int64(v), true
	case int64:
		return v, true
	case float64:
		return int64(v), true
	case string:
		n, err := strconv.ParseInt(v, 10, 64)
		if err == nil {
			return n, true
		}
	}

	return 0, false
}