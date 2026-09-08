# C-/D-Taint 연구 설계 결정

> 아래 규칙은 현재 로그 분석기 구현의 역사적 세부 결정입니다. 최종 의미론과 E1/E2/E3/U 판정은
> [감사 로그 기반 연구 설계](../../RESEARCH_REDESIGN.md)가 우선합니다. 특히 일반 PutObject는
> 명시적 copy 관계가 없으면 E1 D 전파가 아니며, 동일 세션 상관은 E2 후보로만 다룹니다.

이 문서는 구현과 평가에서 의미가 흔들리지 않도록 현재 연구 범위의 결정을 고정한다.

## 1. 분석 단위와 CEM

- 원본 이벤트는 `eventID`로 중복 제거한다. 동일 ID의 CloudWatch Logs/Event History 사본은 한 이벤트로 본다.
- CEM은 actor role session, credential fingerprint, action, outcome, 입력 리소스, 출력 리소스를 분리한다.
- IAM role ARN은 재사용 가능한 principal이고 STS assumed-role ARN은 개별 session이다. C-Taint는 role 전체가 아니라 session과 발급 credential에 부여한다.
- Access key ID와 source IP는 CEM 저장 전에 SHA-256 축약 fingerprint로 바꾼다. secret access key, session token, secret value는 저장하지 않는다.

## 2. C-Taint

- R1-success만 기본 C seed 규칙으로 사용한다. 설정된 S3/Secrets Manager seed에 대한 성공한 `GetObject` 또는 `GetSecretValue`가 session과 credential을 오염시킨다.
- 실패·거부 접근과 `DescribeSecret`은 시도 탐지에는 쓸 수 있지만 기본 C-Taint를 만들지 않는다.
- R2는 C-tainted session의 성공한 `AssumeRole` 응답에서 발급된 session ARN과 accessKeyId를 직접 결합한다. 두 필드가 모두 있으면 `EXACT`다.
- `sourceIdentity`는 추적성 보강 필드이며 기본 전파의 필수 조건이 아니다.
- 자격 증명 만료는 향후 R5에서 edge의 `valid_until`로 표현한다. 과거 taint를 소급 삭제하지 않는다.

## 3. D-Taint

- 최초 D seed는 사전 분류된 중요 데이터 version 또는 보호 대상 논리 자산이다. 순수 HoneyToken은
  침해 접촉을 위한 C seed이며, 실제 중요 데이터를 포함하지 않는 한 자동 D seed가 아니다.
- D 전파는 현재 `CopyObject`의 `x-amz-copy-source`와 목적지 bucket/key가 모두 존재할 때만 `EXACT`로 인정한다.
- 출처를 관측할 수 없는 일반 `PutObject`에는 E1 D-lineage를 부여하지 않는다. 같은 세션의 선행 read가
  있으면 별도 E2 derived 후보로만 기록한다.
- CloudTrail만으로 메모리·애플리케이션 내부 데이터 의존을 증명해야 하는 R6은 현재 `UNSUPPORTED`다.

## 4. 교차점과 판정

- `C_AND_D`: C session이 D-classified/D-lineage 자산을 읽기·수정·삭제·복사한 typed impact event다.
  같은 엔터티의 Boolean 중첩만으로 만들지 않는다.
- `C_ONLY`: 오염 session의 행위지만 관측된 D lineage가 없다.
- `D_ONLY`: C-clean session이 D-tainted 데이터를 다룬다. seedless 공격과 정상 중요 데이터 처리가 섞일 수 있으므로 review 신호다.
- `CLEAN`: 두 taint 모두 없다.
- C∩D만으로 전체 공격을 탐지한다고 주장하지 않는다. S2는 의도적으로 C seed를 우회하므로 D-only가 기대값이다.

## 5. 필드 품질 게이트

| Edge | 필수 필드 | 현재 강등/실패 규칙 |
|---|---|---|
| credential use | `userIdentity.accessKeyId` | 대상 이벤트에 없으면 credential join 제외 |
| role delegation | 응답 session ARN + 발급 accessKeyId | 하나라도 없으면 R2 EXACT 제외 |
| S3 copy lineage | source bucket/key + destination bucket/key | 하나라도 없으면 R7 EXACT 제외 |
| actor session | assumed-role ARN | 없으면 C actor 분류 제외 |

사전 등록된 시나리오 assertion에 필요한 핵심 필드가 하나라도 누락되면 해당 run은 FAIL이다. 보조 KMS 서비스 이벤트처럼 actor가 본질적으로 없는 이벤트는 전체 run 실패 조건이 아니다. 보고서에는 각 필드의 `present/total`을 별도로 기록한다.

## 6. 실험 범위와 제외

- B0 정상 배경, S1-a seed-confirmed 경로, S2 seedless D-only 경로를 구현했다.
- `SourceIdentity` 미사용과 사용 조건을 분리해 관측한다.
- 실제 access key 생성(R3), 권한 지속성/확대(R4), 외부 계정 반출, 공개 버킷 변경, 실제 데이터 사용은 현재 핵심 결론에 필요하지 않고 위험을 넓히므로 실행하지 않는다.
- simulated-egress는 같은 연구 계정의 비공개 버킷이다.
- 현재 결과는 단일 계정의 결정적 합성 실험에 대한 feasibility evidence다. 모집단 precision/recall 또는 일반화 성능으로 해석하지 않는다.
