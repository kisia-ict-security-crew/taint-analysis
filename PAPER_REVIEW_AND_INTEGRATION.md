# 논문 분석과 로그 기반 구현 통합안

대상 논문: 「클라우드 지뢰형 탐지 기술과 비가역적 Taint 기반 침해 영향 추적 구조 제안」
목적: 이론 제안과 현재 GitHub 구현의 차이를 밝히고, 논문에 필요한 설계·평가 항목을 확정한다.

## 1. 논문의 현재 위치

논문은 클라우드 지뢰, 공통 스키마, CSP별 어댑터, C-/D-Taint 및 두 계보의 교차라는 연구 개념을
제시한다. 특히 단일 경보보다 침해 주체의 계보와 중요 데이터 계보가 만나는 지점을 찾는다는 문제 설정은
명확하다.

반면 현재 원고만으로는 다음 질문에 답하기 어렵다.

- Taint가 어떤 저장소에 어떤 식별자로 기록되는가.
- 하나의 API 이벤트에서 다음 이벤트로 무엇을 근거로 전파하는가.
- 거부된 접근, 성공한 접근, 데이터 파생을 어떻게 구분하는가.
- 로그만으로 알 수 없는 경계를 어떻게 처리하는가.
- 공격자가 태그·상태·로그를 삭제하거나 우회하면 무엇이 남는가.
- “저비용”을 어떤 비교군과 측정값으로 검증하는가.
- 여러 CSP를 공통화할 최소 필드와 CSP별 한계는 무엇인가.

따라서 논문은 새로운 실행 경로를 추가하는 시스템이 아니라, 기존 감사 증거에서 Taint 계보를
재구성하는 분석 구조로 구체화한다.

## 2. 최종 제안 구조

```text
Cloud mine / HoneyToken / 중요 자산 registry
                         │
기존 CSP 감사 로그 ──────┼──→ 공통 이벤트 모델(CEM)
                         │              │
                         ▼              ▼
                    원본 증거 저장   Taint 전파 엔진
                                         │
                                         ▼
                              상태·계보·최초 교차점
                                         │
                                         ▼
                                  경보·조사 보고서
```

업무 요청은 기존 CSP API로 그대로 처리한다. Taint는 업무 데이터 안이나 요청 헤더에 삽입하지 않고,
감사 이벤트와 seed registry를 근거로 외부 상태에 누적한다. 분석 장애가 업무 가용성을 떨어뜨리지 않는
비동기 구조가 저비용·비침습 목적에 부합한다.

## 3. 공통 이벤트 모델

멀티클라우드 공통화는 모든 필드를 동일하게 만드는 것이 아니라, 전파 판정에 필요한 최소 의미를
정규화하는 작업이다.

```text
event_id
event_time
ingest_time
provider
account_or_tenant
service
action
success
actor_instance_id
session_id
source_resource
destination_resource
resource_version
parent_session_id
request_parameters_digest
evidence_reference
```

원문 자격증명, secret, payload는 CEM에 넣지 않는다. CSP 원본 이벤트는 변경하지 않고 증거 저장소에
보존하며 CEM 레코드는 원본 위치와 hash를 참조한다.

AWS에서는 CloudTrail `eventID`, `eventTime`, `eventSource`, `eventName`, `errorCode`,
`userIdentity`, `requestParameters`, `responseElements`, `resources` 등을 위 필드로 변환한다.
Azure·GCP·Naver Cloud는 동일 의미의 필드가 실제로 존재하는지 별도의 coverage 표로 검증한다.

## 4. Taint 저장과 비가역성

저장 구조는 세 계층으로 나눈다.

| 계층 | 내용 | 역할 |
|---|---|---|
| 증거 저장 | CSP 원본 감사 로그 | 재분석과 판정 검증의 기준 |
| seed registry | HoneyToken 및 중요 자산의 연구 ID·정확한 resource version | C/D 시작점 |
| 상태·계보 | C 주체, D-classified 자산, D-lineage 데이터, exposure, typed edge, 최초 교차 | 분석 결과 |

비가역성은 리소스 태그를 삭제하지 못하게 한다는 뜻이 아니다. 같은 엔터티 생애에서 원인 집합을
추가만 하는 단조 join과, 과거 판정을 삭제하지 않는 append-only 이력으로 정의한다.

```text
C(subject)      = set of compromise/control seed IDs
D_class(asset)  = set of protected-asset seed IDs
D_lineage(data) = set of source-data seed IDs
intersection(event) iff a C subject performs an impact action on D-class/D-lineage
```

D-class는 보호 대상으로 지정된 논리 자산이고 D-lineage는 특정 중요 데이터 version에서 직접 이어진
내용 계보다. 세션이 D를 읽었다는 사실은 세션에 D 객체 label을 붙이지 않고 exposure edge로 기록한다.

S3 객체는 bucket/key만으로 식별하면 overwrite를 구분하지 못하므로 version ID를 포함한다. 세션은
공유 IAM Role이 아니라 발급된 credential instance 또는 session ARN을 사용한다. 원문 access key는
노출하지 않고 fingerprint만 저장한다.

## 5. 전파 의미론

### C 계보

- 등록 미끼의 성공한 취득은 해당 세션의 C seed다.
- 실패·거부·목록 조회는 접촉 시도이며 C-success와 분리한다.
- C 세션이 AssumeRole로 발급한 자식 세션을 응답 식별자로 연결할 수 있으면 C를 전파한다.
- 같은 IP, 역할 이름, user-agent 또는 시간 근접성만으로 C를 전파하지 않는다.

### D 계보

- 등록된 중요 객체 version은 D seed다.
- 중요 객체의 성공한 읽기는 객체에서 세션으로의 노출 edge다.
- CopyObject처럼 원본과 목적지가 한 이벤트에 나타나면 목적 객체로 D를 전파한다.
- GetObject 후 애플리케이션이 PutObject를 수행한 경우 로그만으로 byte 의존성을 확인할 수 없으므로
  정확 전파가 아니라 추정 후보로 분리한다.

### 최초 교차

- C 세션이 D 객체를 성공적으로 읽는 최초 이벤트는 접근 교차점이다.
- C 세션이 D 객체를 명시적으로 복사해 새 D 객체를 만드는 이벤트는 계보 교차점이다.
- 단순 권한 보유, 거부된 요청 또는 동일 네트워크 위치는 교차점이 아니다.

## 6. 증거 수준과 관측 공백

| 수준 | 논문 표현 | 사용 가능 결과 |
|---|---|---|
| E1 EXACT | 직접 인과관계 | 주 precision/recall 및 최초 교차 결과 |
| E2 INFERRED | 제한된 추론 | 후보 수와 과도 전파율 |
| E3 OBSERVED | 접촉·접근 관측 | 보조 경보 |
| U UNSUPPORTED | 로그로 판정 불가 | coverage 공백 |

논문의 중요한 기여는 모든 경계를 지원했다고 주장하는 데 있지 않다. 어떤 경계는 정확히 추적되고,
어떤 경계는 추정만 가능하며, 어디부터 추가 계측이 필요한지를 공개하는 coverage matrix 자체가 실제
도입 가능성을 높인다.

## 7. 훼손과 우회에 대한 설계

Taint 결과만 보호해서는 충분하지 않다. 판정의 근거인 로그와 registry도 보호해야 한다.

- 원본 로그: 별도 로그 계정, KMS, bucket versioning, Object Lock 선택, CloudTrail log validation
- 수집기: 원본 로그 read-only, 최소 권한, eventID 중복 제거
- 상태: 조건부 단조 update, 과거 edge 삭제 금지, 정정은 superseding record
- 식별정보: secret·token·payload 미저장, access key fingerprint 사용
- 감시: Trail 중지, selector 축소, 버킷 정책·KMS·보존기간 변경도 보안 이벤트로 수집

조직 관리 계정이나 로그 보관 계정까지 침해된 경우는 신뢰 경계 밖으로 명시한다. 로그가 없거나
식별자가 끊긴 구간은 자동으로 추정해 메우지 않는다.

## 8. 저비용 연구 주장

논문의 비용상 강점은 데이터 경로에서 동작하는 전면적 정보흐름 제어보다 낮은 보장을 제공하는 대신,
기존 감사 기반에서 실제 조사에 필요한 교차점을 희소하게 찾는 데 있다.

```text
비용 = 기존 관리 로그
     + 선택한 지뢰·중요 자산 데이터 이벤트
     + 변경된 Taint 상태와 최초 교차점 처리
     + 증거 보존
```

이를 입증하려면 관리 로그만, 전체 데이터 이벤트, 선택 데이터 이벤트, 선택 수집+Taint 분석의 네
구성을 같은 workload에서 비교한다. 비용과 함께 E1 coverage를 보고해야 하며, 로그 범위를 줄여 놓고
비용 절감만 제시해서는 안 된다.

## 9. 현재 GitHub 구현과 부족한 부분

### 이미 있는 부분

- Terraform 기반 CloudTrail, S3, KMS, CloudWatch, EventBridge/SNS, Athena 환경
- 합성 HoneyToken·중요 객체 및 역할 전환 시나리오
- CloudTrail을 CEM으로 변환하는 분석기
- C 세션, STS 역할 전환, D 접근·복사 및 C∩D 판정의 초기 규칙
- 정상 배경, C∩D, D-only 시나리오의 실제 AWS 로그 기반 결과

### 논문 결과 전에 보강할 부분

- Boolean label을 seed 원인 집합으로 변경
- 모든 edge에 E1/E2/E3/U와 원본 eventID 기록
- S3 object version 식별과 최초 교차 edge 저장
- 성공 접촉과 거부 시도 분리
- read-transform-write를 E1로 과장하지 않는 규칙과 음성 대조군
- 선택 수집과 전체 수집의 실제 이벤트 수·비용 비교
- 조건별 반복, 신뢰구간, precision/recall 및 과도 전파율
- AWS 외 CSP의 실제 필드 mapping과 coverage 검증

## 10. 논문 평가 설계

### 연구 질문

- RQ1: 로그가 직접 제공하는 관계만 사용했을 때 C/D 전파와 최초 교차점을 정확히 찾을 수 있는가?
- RQ2: E1/E2/E3/U 분리가 false propagation과 관측 공백을 설명하는가?
- RQ3: 선택 수집이 필요한 E1 coverage를 유지하면서 전체 데이터 이벤트 수집보다 비용을 줄이는가?
- RQ4: 공통 이벤트 모델이 CSP별 의미 손실과 미지원 필드를 명시하면서 이식 가능한가?

### 필수 시나리오

- 정상 배경 B0
- HoneyToken 성공·거부 C1/N1
- HoneyToken→AssumeRole C2
- 중요 객체 읽기 D1
- 중요 객체 명시적 복사 D2
- C 세션의 중요 객체 접근·복사 CD1/CD2
- 동일 IP의 독립 세션 N2
- 중요 데이터 읽기 후 무관한 출력 N3

### 결과표

- 시나리오별 기대/실제 C와 D 원인
- 최초 교차 eventID, eventTime, edge type, 증거 수준
- E1 precision/recall, E2 과도 전파율
- 수집 누락과 U 경계 비율
- 판정 지연 p50/p95
- 구성별 이벤트 수, 저장량, 처리량 및 추정·실측 비용

## 11. 논문에서 유지할 강점과 수정할 표현

유지할 강점은 HoneyToken을 단순 경보가 아니라 침해 계보의 시작점으로 사용하고, 이를 중요 데이터
계보와 결합해 조사 우선순위를 만든다는 점이다. 멀티클라우드 공통 모델도 장기적인 확장 기여가 될 수
있다.

다만 “모든 이동”, “완전한 비가역성”, “실시간 추적”, “멀티클라우드 적용 완료” 같은 표현은 현재
근거보다 강하다. 대신 다음처럼 제한해 기술한다.

> 본 연구는 기존 클라우드 실행 경로를 변경하지 않고 선택적으로 수집한 감사 이벤트에서 C-/D-Taint
> 계보를 재구성한다. 직접 인과관계가 있는 경계는 정확 전파하고, 데이터 의존을 관측할 수 없는 경계는
> 추정 또는 미지원으로 분리한다. 이를 통해 제한된 추가 비용으로 HoneyToken 접촉과 중요 데이터 접근의
> 최초 교차점을 식별하고 조사 범위 감소 가능성을 평가한다.

이 문장을 논문의 문제 정의, 시스템 설계, 구현, 실험 및 결론이 모두 공유해야 한다.
