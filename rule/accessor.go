package rule

import "mini_edr/model"

// GetEventField는 Rule 조건 key를 SystemEvent의 실제 필드 값으로 변환한다.
// RuleEngine은 더 이상 SystemEvent 내부 구조를 직접 알 필요 없이,
// 이 함수만 통해 조건 비교 값을 가져온다.
func GetEventField(event *model.SystemEvent, key string) (interface{}, bool) {
	switch key {
	case "exe":
		return event.ImagePath, true

	case "ppid_exe":
		return event.ParentImage, true

	case "argv":
		return event.CommandLine, true

	case "path", "pathname":
		if event.PathName != "" {
			return event.PathName, true
		}
		return event.TargetFile, true

	case "request":
		return event.Request, true

	case "euid":
		return event.EUID, true

	case "egid":
		return event.EGID, true

	case "protocol":
		return event.Protocol, true

	case "dest_ip":
		return event.DstIP, true

	case "dest_port":
		return event.DstPort, true

	default:
		return nil, false
	}
}