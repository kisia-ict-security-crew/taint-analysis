# 후속 이론·평가 과제

> 초기 과제 목록입니다. 현재 우선순위와 증거 수준은 [최종 연구 설계](../../RESEARCH_REDESIGN.md)입니다.
> 아래 "실물 로그 확인/feasibility 비교 완료" 주장은 현재 저장소에 실제 실행 산출물이 없어
> 독립 검증되지 않았습니다. 최종 논문의 완료 근거로 사용하지 않습니다.

핵심 구현에 필요한 의미론은 [DECISIONS.md](DECISIONS.md)에 고정했고 B0, S1-a, S2 및 SourceIdentity 개입 실험까지 구현했다. 아래 항목은 통계적 일반화와 범위 확장을 위해 남은 후속 연구다.

## 완료된 결정

- CEM의 단일 `target`을 역할이 있는 복수 `resources[]`로 변경한다. COPY는 source와 destination을 모두 보존한다.
- IAM role ARN, STS session ARN, access key ID를 각각 principal, session, credential로 분리한다.
- R5는 과거 taint 삭제가 아니라 credential edge의 `valid_until`을 닫는 시간 규칙으로 정의한다.
- DIRECT와 DETERMINISTIC_JOIN을 모두 EXACT 후보로 인정하고, 시간/IP 기반 결합만 APPROX로 둔다.
- 벤더 능력, 실험 로깅 구성, 실제 필드 존재율을 서로 다른 표로 보고한다.
- R1-success, R1-attempt, 탐지 전용 credential honeytoken을 분리한다.
- R6는 CloudTrail-only 환경에서 데이터 의존을 직접 증명하지 못하므로 기본 UNSUPPORTED로 고정한다.
- R4는 첫 실험에서 단일 계정·직접 인라인 Allow·boundary/SCP/Deny 없음으로 scope를 제한한다.

## 추가 측정 설계

- 위임 edge, credential issuance/use, COPY lineage, X1 각각의 precision/recall 분모를 사전에 고정한다.
- 동일 시나리오를 여러 번 반복하고 CloudTrail 전달 지연과 핵심 필드 결측률을 함께 보고한다.
- B0 전체, B1 시간창, B2 시작 주체만 기준선을 같은 데이터에서 계산한다.
- sourceIdentity 미사용 기본 조건과 사용 조건의 feasibility 비교는 완료했다. 반복 표본으로 결측률과 효과 크기를 추가 측정한다.
- S2의 기대값은 미끼 기반 검출 0이다. 보조 taint source를 추가하지 않는다.
- CloudTrail addendum, 동일 eventID 중복, cross-account sharedEventID 처리 방침을 고정한다.

## 통과한 구현 게이트

1. 실물 로그에서 AssumeRole 발급 `accessKeyId`와 후속 `userIdentity.accessKeyId` 연결을 확인한다.
2. CopyObject 원본과 목적지를 모두 CEM에 보존할 수 있음을 확인한다.
3. 모든 핵심 필드의 결측률 임계값과 강등 기준을 DECISIONS.md에 기록한다.
4. 위 세 조건을 만족한 CEM adapter와 taint engine을 구현했다. 공개 릴리스 시 스키마 버전 태그를 부여한다.
