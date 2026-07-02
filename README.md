# mini_edr
mini-edr/
├── go.mod
├── go.sum
├── README.md
│
├── cmd/
│   └── agent/
│       └── main.go                  # 최상위 구동 및 라이프사이클 제어
│
├── collector/                       # ──> (1) Collector 영역
│   ├── types.go                     # 수집에 필요한 상수 및 규칙 매트릭스 정의
│   ├── errors.go                    # errors.Is/As 표준 커스텀 에러 엔진
│   ├── collector.go                 # Collector 표준 인터페이스 규격 선언
│   ├── tail_collector.go            # [1단계] audit.log 맨 끝단 실시간 Raw 추출기
│   ├── auditd_collector.go          # [2단계] 감사 ID별 파편 조립기
│   └── collector_test.go            # 수집 레이어 통합 테스트 코드
│
├── dispatcher/                      # ──> (2) Event Dispatcher & (4) Alert Dispatcher 영역
│   ├── event_dispatcher.go          # [3단계] 조립 가방 ➔ 구조체 정형 가공 및 파싱 라우터 (기존 parser.go)
│   ├── alert_dispatcher.go          # 위협 탐지 시 Response와 Storage로 비동기 팬아웃(Fan-out) 토스
│   └── dispatcher_test.go
│
├── model/                           # ──> 공통 데이터 모델 영역
│   └── event.go                     # SyscallRecord 등 파편 모델 및 최종 SystemEvent 완제품 정의
│
├── rule/                            # ──> (3) Rule Engine 영역
│   ├── engine.go                    # 규칙 엔진 코어 (메모리 로드 및 매칭)
│   ├── ioc_matcher.go               # 해시, 파일 경로 등 침해 지표 대조기
│   └── ioa_matcher.go               # 프로세스 연쇄 행위 등 공격 지표 대조기
│
└── engine/                          # ──> (5) Response Engine & (6) Storage & Transmit Engine 영역
    ├── response_engine.go           # 즉각 프로세스 Kill 및 파일 권한 제한/격리 조치 수행
    └── storage_transmit_engine.go   # JSON 정형화 로컬 저장 및 웹/서버 원격 HTTP POST 전송