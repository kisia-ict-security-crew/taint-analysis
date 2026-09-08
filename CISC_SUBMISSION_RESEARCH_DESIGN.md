# CISC 제출용 C-/D-Taint 연구·실험 설계서

상태: 제출 논문 구현 및 평가 기준

## 1. 연구 제목

권장 제목:

> 클라우드 감사 로그 기반 C-/D-Taint 교차를 이용한 저비용 침해 영향 추적

영문 제목:

> Low-Cost Cloud Incident Impact Tracing through C-/D-Taint Intersections in Audit Logs

“비가역적”, “모든 자산”, “실시간”, “멀티클라우드 구현”은 현재 검증 범위를 넘으므로 제목과 핵심
주장에서 제외한다.

## 2. 문제 정의

HoneyToken 접촉은 침해 가능성이 높은 주체를 알려주지만 그 주체가 실제 중요 자산에 영향을 주었는지는
알려주지 않는다. 반대로 중요 데이터 접근 로그는 데이터의 이동을 보여주지만 정상 백업·ETL과 공격을
구분하기 어렵다.

본 연구는 두 계보를 독립적으로 유지한 뒤, 침해 계보의 주체가 중요 자산에 영향 행위를 수행한 최초
감사 이벤트를 찾는다.

```text
C-Taint: 누가 침해 시작점의 영향을 받았는가?
D-Taint: 무엇이 중요 데이터이며 어디로 명시적으로 이동했는가?
교차점:  C 주체가 D 자산에 언제 어떤 영향을 처음 주었는가?
```

## 3. 연구 목적

기존 AWS 업무 요청 경로를 변경하지 않고 다음을 달성한다.

1. 성공한 HoneyToken 접촉에서 시작한 C 계보를 credential/session 전환을 따라 추적한다.
2. 중요 데이터에서 시작한 D 계보를 명시적 데이터 이동 관계를 따라 추적한다.
3. C 주체가 D 자산을 읽기·수정·삭제·복사한 최초 typed intersection을 식별한다.
4. C-only, D-only보다 교차점 분석이 중요 침해 영향의 조사 후보를 줄이는지 검증한다.
5. 전체 데이터 이벤트 수집보다 선택 수집이 필요한 coverage를 유지하면서 비용을 줄이는지 검증한다.
6. 파생 Taint 상태가 훼손되어도 검증된 원본 로그에서 같은 결과를 재구성할 수 있는지 확인한다.

## 4. 연구 기여

논문에서 주장할 기여는 세 가지로 제한한다.

1. **분리된 의미론:** HoneyToken 기반 침해·제어 계보 C와 중요 데이터 계보 D를 분리한다.
2. **Typed intersection:** 단순 Boolean 중첩 대신 `READ/WRITE/DELETE/COPY` 영향 사건을 식별한다.
3. **저비용 감사 기반 평가:** 기존 실행 경로를 변경하지 않고 선택 수집의 정확도·비용·지연·coverage를 함께 측정한다.

이중 label 자체는 신규성으로 주장하지 않는다. 기존 provenance 연구도 신뢰도와 기밀성 tag를 분리해
공격 탐지와 영향 분석에 사용했다. 본 연구의 차별점은 HoneyToken을 C seed로 사용하고, 관리형
클라우드 감사 로그의 제한된 인과관계 안에서 최초 typed intersection과 선택 수집 비용을 평가하는 데 있다.

## 5. 범위

### 5.1 핵심 구현 범위

| 역할 | AWS 리소스·로그 |
|---|---|
| C seed | S3 Honey object, Secrets Manager Honey secret |
| C 전파 | STS AssumeRole parent→child session |
| D seed | versioning된 중요 S3 object와 보호 대상 logical key |
| D 전파 | S3 CopyObject source→destination |
| 영향 행위 | S3 GetObject, PutObject, DeleteObject, CopyObject |
| 증거 | CloudTrail 관리 이벤트와 선택된 S3 데이터 이벤트 |
| 저장 | 암호화된 S3 원본 로그와 외부 Taint 상태·edge |

### 5.2 제외 범위

- 실제 자격증명과 실제 개인정보
- 공개 버킷과 외부 계정 반출
- Lambda 내부 payload lineage
- SQS/SNS message payload lineage
- RDS row·transaction lineage
- EKS/EC2 process·file·memory lineage
- Azure, GCP, Naver Cloud의 구현 완료 주장
- 모든 byte의 end-to-end 정보흐름 추적

제외 리소스는 지원 실패가 아니라 이번 논문의 평가 범위 밖이다. 리소스별 가능성과 관측 공백은 저장소의
구현 부록으로 남기되 논문 본문에는 넣지 않는다.

## 6. Taint 의미론

### 6.1 C-Taint

C는 침해 또는 공격자 제어의 계보다.

```text
C(subject) = set of compromise seed IDs
```

- 대상: credential instance, STS session
- seed: 등록된 HoneyToken의 성공한 취득
- 전파: 직접 확인한 parent→child credential 발급
- footprint: C subject가 수행한 resource 생성·수정·삭제
- 전파 금지: 동일 IAM Role, IP, user-agent, 계정, 시간 근접성

거부된 Honey 접근과 `DescribeSecret`은 접촉 시도일 뿐 C seed가 아니다.

### 6.2 D-Taint

D는 자산 중요도와 데이터 계보다.

```text
D_class(asset)  = protected logical asset seed IDs
D_lineage(data) = source data seed IDs
```

- `D-CLASSIFIED`: 보호 대상으로 등록한 S3 logical key
- `D-LINEAGE`: 중요 object version 또는 그 version에서 명시적으로 복사된 version
- `D-EXPOSURE`: 어떤 session이 어떤 D object를 읽었는지 나타내는 관계

D object를 읽은 session에 D 객체 label을 붙이지 않는다. 같은 session의 모든 후속 출력이 중요 데이터라고
확정되는 과도 전파를 막기 위해서다.

### 6.3 단조성

```text
L_new(entity) = L_old(entity) union incoming_seed_ids
```

같은 entity generation에서는 원인을 삭제하지 않는다. 새 session, 새 object version은 별도 entity다.
오판 정정은 기존 edge 삭제가 아니라 `SUPERSEDED_BY` 레코드로 추가한다.

## 7. Typed intersection

교차점은 다음 조건을 만족하는 event다.

```text
Intersection(event) = C(actor)
                    AND D_class/D_lineage(target or source)
                    AND impact_action(event)
```

| 유형 | 조건 | 보안 영향 | 주장 한계 |
|---|---|---|---|
| `READ` | C session이 D object GET 성공 | 기밀성 노출 가능성 | 외부 유출 확정 아님 |
| `WRITE` | C session이 D-classified key 수정 | 무결성 훼손 가능성 | 새 내용이 D-lineage라는 뜻 아님 |
| `DELETE` | C session이 D object/key 삭제 | 가용성 훼손 | 복구 불가능 확정 아님 |
| `COPY` | C session이 D-lineage source를 명시적으로 복사 | 중요 데이터 확산 | 외부 반출 확정 아님 |

`GetObject→애플리케이션 변환→PutObject`는 CloudTrail만으로 byte 의존성을 확인할 수 없으므로 E1
교차가 아니다. 같은 session·제한 시간창은 E2 `DERIVE` 후보로만 기록한다.

## 8. 왜 교차점을 평가하는가

C-only는 공격 영향 범위를 넓게 보여주지만 중요 자산 영향 여부를 구분하지 못한다. D-only는 중요 데이터
흐름을 보여주지만 정상 업무와 공격을 구분하지 못한다. Typed intersection은 두 분석을 대체하지 않고
중요 침해 영향의 우선 조사 대상을 만든다.

```text
C-only → 침해 확산·권한·비중요 리소스 훼손
D-only → 중요 데이터의 정상·미분류 흐름
C∩D    → 침해 주체가 중요 자산에 준 실현된 영향
```

최초 교차점은 역방향 침입 경로와 순방향 영향 경로를 나누는 조사 기준점이며, Honey 접촉부터 중요
영향까지의 time-to-impact를 제공한다.

교차하지 않았다는 이유로 안전하다고 판정하지 않는다. HoneyToken을 우회한 공격은 D-only로, 중요
데이터에 접근하지 않은 파괴 행위는 C-only로 남을 수 있다.

## 9. 증거 등급

| 등급 | 의미 | 결과 사용 |
|---|---|---|
| `E1 EXACT` | 직접 식별자 또는 source→destination 존재 | 주 정확도·교차 결과 |
| `E2 INFERRED` | 같은 실행 단위·제한 시간으로 추론 | 후보·과도 전파율 |
| `E3 OBSERVED` | 시도·변경·거부 사실 | 보조 경보 |
| `U UNSUPPORTED` | 필요한 필드·로그 없음 | coverage 공백 |

E1과 E2 상태는 분리한다. E2 후보는 이후 E1 전파의 입력으로 사용하지 않는다.

## 10. 시스템 구조

```text
기존 AWS API 활동
        │
        ▼
CloudTrail management + scoped S3 data events
        │
        ├── 원본 로그·digest → 암호화 S3
        ▼
Cloud Event Model 정규화·eventID 중복 제거
        ▼
C seed / C control / C footprint
D seed / D copy / D exposure
        ▼
typed first intersection
        ▼
C-only / D-only / C∩D 보고서와 우선순위
```

분석 경로는 비동기다. 장애가 기존 업무 요청을 막지 않는다. CloudTrail 이벤트는 순서대로 도착한다고
가정하지 않고 fixed-point 재전파와 late-event 재처리를 수행한다.

## 11. 저장 구조

| 저장 계층 | 내용 | 권위 |
|---|---|---|
| S3 evidence | 변경하지 않은 CloudTrail 원본과 digest | 최종 증거 |
| seed registry | C/D seed ID, resource version, 정책 version | 시작점 |
| subject state | session별 C source 집합 | 파생 상태 |
| data state | D-class/D-lineage source 집합 | 파생 상태 |
| edge | control, footprint, exposure, copy, impact | 계보 |
| first intersection | C seed×D seed별 최초 typed edge | 주요 결과 |

원문 access key, secret value, session token, 객체 payload를 상태 저장소나 Git 결과에 저장하지 않는다.
access key는 fingerprint로 바꾼다. 리소스 tag는 선택적 projection이며 권위 상태가 아니다.

## 12. 최소 전파 규칙

| 규칙 | 조건 | 출력 |
|---|---|---|
| R1 `C-SEED` | 성공한 HoneyToken 취득 | actor session에 C |
| R2 `C-CONTROL` | C parent가 child credential 발급 | child session에 C |
| R3 `C-FOOTPRINT` | C actor가 resource 변경 | C 영향 edge |
| R4 `D-SEED` | 등록 중요 asset/version | D-class/D-lineage |
| R5 `D-COPY` | 명시적 source→destination copy | destination D-lineage |
| R6 `IMPACT` | C actor의 D READ/WRITE/DELETE/COPY | typed intersection |

이 여섯 규칙 이외의 전파는 기본적으로 만들지 않는다.

## 13. 연구 질문과 가설

### RQ1. C와 D를 독립적으로 정확히 구분할 수 있는가?

- H1: Honey 접촉만 발생한 사건은 C-only이고 D가 생성되지 않는다.
- H2: 정상 중요 데이터 접근은 D-only이며 C가 생성되지 않는다.

### RQ2. Typed intersection이 중요한 침해 영향 조사에 유용한가?

- H3: typed intersection은 C-only 또는 D-only보다 중요 침해 영향 precision이 높다.
- H4: typed intersection은 정답 중요 영향 recall을 유지하면서 조사 후보 수를 줄인다.

### RQ3. 최초 교차점을 정확히 식별할 수 있는가?

- H5: E1 범위에서 최초 교차 eventID와 유형이 정답 manifest와 일치한다.

### RQ4. 선택 수집은 비용상 유리한가?

- H6: scoped data event는 전체 data event보다 적은 비용으로 같은 E1 교차점을 유지한다.

### RQ5. Taint 결과는 훼손 후 재구성 가능한가?

- H7: 파생 상태를 제거한 뒤 검증된 원본 로그를 재처리하면 동일한 결과 hash가 생성된다.

## 14. 실험 시나리오

모든 행위는 전용 연구 계정의 합성 리소스에서 수행한다.

| ID | 실행 경로 | 정답 |
|---|---|---|
| B0 | Honey·중요 자산과 무관한 정상 S3 작업 | CLEAN |
| C1 | Honey GET 성공→일반 조회 | C-only |
| C2 | Honey GET→AssumeRole 2단계→일반 작업 | C-only control propagation |
| D1 | 독립 정상 session→중요 object GET | D-only exposure |
| D2 | 독립 정상 session→중요 object COPY | D-only lineage |
| X1 | C session→중요 object GET | E1 `READ` |
| X2 | C session→중요 logical key PUT | E1 `WRITE` |
| X3 | C session→중요 object DELETE | E1 `DELETE` |
| X4 | C session→중요 object COPY | E1 `COPY` |
| X5 | C session→중요 GET→로컬 변환→PUT | E2 `DERIVE`, E1 금지 |
| N1 | Honey GET AccessDenied | E3 attempt, C 없음 |
| N2 | C와 같은 IP·role의 독립 session | C 전파 없음 |
| N3 | Honey를 우회한 미분류 session→중요 GET | D-only, C coverage 한계 |
| T1 | resource tag 삭제 | 권위 Taint 불변 |
| T2 | 파생 상태 삭제 후 원본 로그 replay | 동일 결과 복구 |
| T3 | 로그 순서 변경·중복 입력 | 동일 결과 |
| T4 | selector/Trail 설정 변경 시도 | evidence-integrity 경보 |

X2·X3은 합성 중요 객체의 별도 실험 version에서만 수행하고 원본 정답 데이터는 보존한다.

## 15. 정답지와 반복

실행기는 run마다 다음 manifest를 먼저 만든다.

```text
run_id
scenario
actor session names
expected event names
expected source/destination resource versions
expected C seeds
expected D seeds
expected intersection type
start/end time
```

manifest는 정답 판정에만 사용하고 Taint 엔진 입력으로 사용하지 않는다. 엔진은 원본 감사 로그와 seed
registry만 읽는다.

각 조건은 최소 30회 반복하거나 별도의 표본 수 근거를 제시한다. 결과에는 성공 비율만 쓰지 않고 95%
신뢰구간, 누락 event 수, CloudTrail 전달 timeout을 함께 보고한다.

## 16. 교차점 필요성 검증: ablation

동일 이벤트 집합을 다음 네 방식으로 분석한다.

| 분석군 | 사용하는 정보 |
|---|---|
| A C-only | C seed와 C control/footprint |
| B D-only | D seed와 D exposure/copy |
| C C+D union | A와 B의 모든 후보를 단순 합산 |
| D typed C∩D | C actor+D asset+impact action 모두 충족 |

측정식:

```text
Precision_C = 실제 중요 침해 영향 / C-only 후보
Precision_D = 실제 중요 침해 영향 / D-only 후보
Precision_X = 실제 중요 침해 영향 / typed intersection 후보

Recall_X = 탐지한 중요 침해 영향 / 정답 중요 침해 영향

Candidate_Reduction
  = 1 - (typed intersection 후보 수 / C+D union 후보 수)

Time_to_Impact
  = first intersection eventTime - C seed eventTime
```

H3·H4는 `Precision_X`, `Recall_X`, 후보 감소율을 모두 보고한 뒤 판정한다. 후보 수만 줄고 recall이 크게
떨어지면 성공이 아니다.

## 17. 정확성 평가

다음 단위로 confusion matrix를 만든다.

- C session classification
- D object-version classification
- D exposure edge
- D copy edge
- typed impact edge
- first intersection event

E1과 E2는 별도 confusion matrix를 사용한다. 구현 범위 밖 event를 false negative로 숨기지 않고
`NO_COVERAGE`로 별도 집계한다.

필수 결과표:

| Scenario | Runs | Expected | Detected | FP | FN | Precision | Recall | Missing logs |
|---|---:|---|---|---:|---:|---:|---:|---:|

## 18. 비용·지연 평가

### 18.1 비교 구성

| 구성 | 수집 범위 |
|---|---|
| L0 | 관리 이벤트만 |
| L1 | 연구 S3 bucket 전체 데이터 이벤트 |
| L2 | Honey·중요 자산으로 제한한 데이터 이벤트 |
| L3 | L2 + Taint 분석·상태 저장 |

같은 API workload, 기간, 리전, 보존기간으로 비교한다.

### 18.2 측정값

- 관리·데이터 event 수
- 원본 로그 byte와 상태 byte
- S3/KMS/CloudTrail/분석 요청 수
- 분석 실행 시간과 처리 event 수
- seed→CloudTrail 수집 지연 p50/p95
- seed→교차 판정 지연 p50/p95
- 백만 업무 API 및 백만 수집 event당 추정 비용
- 구성별 E1 coverage

공식 서울 리전 단가를 실행일과 함께 기록하고 bottom-up 계산을 사용한다. 충분히 긴 반복에서는
CUR/Cost Explorer와 대조한다. 무료 구간과 일시 할인은 일반 비용 우위 근거로 사용하지 않는다.

## 19. Taint 훼손·재구성 평가

| 시험 | 통과 조건 |
|---|---|
| 상태 reset | 원본 로그 replay 후 같은 state·intersection hash |
| tag 삭제 | 외부 권위 상태와 원본 edge 유지 |
| event 중복 | eventID dedup 후 결과 불변 |
| event 순서 변경 | fixed-point 처리 후 결과 불변 |
| denied event 삽입 | C-success·D-success 증가 없음 |
| selector/Trail 변경 | 별도 evidence-integrity 경보 생성 |
| CloudTrail validation | 대상 시간창 digest 검증 성공 |

“비가역적 Taint” 대신 “엔터티 생애에서 단조 누적되고 검증된 원본 로그에서 재구성 가능한 Taint”라고
표현한다. 실제 로그 삭제 방지는 별도 로그 계정·Object Lock 등 배포 조건에 의존한다.

## 20. 실험 통과 기준

논문 결과로 사용하려면 다음을 모두 만족해야 한다.

1. C1·C2는 C-only이며 Honey 자체가 D가 아니다.
2. D1·D2는 D-only이며 C가 생성되지 않는다.
3. X1~X4의 eventID와 교차 유형이 정답과 일치한다.
4. X5는 E1 D-lineage 또는 E1 교차로 승격되지 않는다.
5. N1·N2에서 C false propagation이 없다.
6. N3을 안전으로 판정하지 않고 seed coverage 한계로 보고한다.
7. typed intersection의 precision·recall과 후보 감소율을 모두 제시한다.
8. L2/L3의 비용 감소와 L1 대비 유지된 coverage를 함께 제시한다.
9. T2·T3에서 같은 결과 hash를 재현한다.
10. 계정 ID, ARN, access key, IP, secret, payload가 공개 결과에 포함되지 않는다.

하나라도 실패하면 원인을 공개하고 주장 범위를 낮춘다.

## 21. 현재 구현과 필요한 변경

### 구현됨

- Terraform 기반 CloudTrail·S3·KMS·CloudWatch·EventBridge/SNS·Athena 환경
- 합성 Honey object, Honey secret, 중요 object
- A→B→C STS session 시나리오
- CloudTrail→CEM 정규화와 eventID 중복 제거
- 성공 C seed와 AccessDenied 음성 판정
- 순수 Honey=C-only, 중요 object=D seed 분리
- STS C 전파와 명시적 S3 CopyObject D 전파
- C-only, D-only, C∩D의 초기 분류

### 제출 전 필수 구현

1. Boolean 집합을 `c_sources`, `d_classified`, `d_lineage`로 분리한다.
2. session에는 D label 대신 `D-EXPOSURE` edge를 저장한다.
3. E1/E2/E3/U와 원본 eventID를 모든 edge에 기록한다.
4. `READ/WRITE/DELETE/COPY` typed intersection을 구현한다.
5. C seed×D seed별 first intersection을 조건부 저장한다.
6. X1~X5, N1~N3, T1~T4 runner와 assertion을 구현한다.
7. 조건별 반복·ablation·비용·지연 집계기를 구현한다.
8. 과거 AWS 원본 로그를 새 seed 정책으로 재분석한다.

기존 분석 결과는 Honey seed가 D seed에도 포함됐던 구정책에서 생성됐으므로 최종 정량 결과로 사용하지
않는다. 원본 로그가 남아 있으면 새 정책과 동일 analyzer version으로 다시 생성한다.

## 22. 논문 3~4쪽 구성

| 분량 | 내용 |
|---:|---|
| 0.5쪽 | 문제, C-only/D-only의 한계, 기여 3개 |
| 0.5쪽 | 관련 연구와 차별점 |
| 0.75쪽 | C/D 의미론, 6개 규칙, typed intersection 그림 |
| 0.5쪽 | AWS 구현·위협 모델·증거 등급 |
| 1.0쪽 | 정확성·ablation·비용·지연·훼손 결과 표와 그래프 |
| 0.25쪽 | 한계와 결론 |

본문에서 제거할 내용:

- 지뢰 marketplace의 상세 기능
- 모든 CSP·리소스 adapter 목록
- 구현하지 않은 EKS/RDS/message/process 설계
- 요청 경로를 바꾸는 구조
- 정량 근거 없는 “획기적”, “완전”, “실시간”, “저비용” 표현

## 23. 결과에 따른 허용 주장

### 결과 전에도 가능한 표현

- C와 D의 분리된 의미론을 제안했다.
- 감사 로그 기반 typed intersection 설계를 제안했다.
- AWS 제한 범위의 prototype을 구현했다.

### 결과가 있어야 가능한 표현

- 교차 분석이 조사 후보를 줄였다.
- E1 범위에서 최초 교차를 정확히 찾았다.
- 선택 수집이 전체 수집보다 비용을 줄였다.
- 상태 훼손 후 동일 결과를 재구성했다.

### 현재 사용하면 안 되는 표현

- 모든 클라우드 리소스를 추적한다.
- 모든 침해를 탐지한다.
- 실제 데이터 유출을 확정한다.
- 완전한 비가역성을 보장한다.
- 기업 환경 전체에서 비용 우위가 입증됐다.

## 24. 최종 논문용 핵심 문장

> 본 연구는 HoneyToken 접촉에서 시작한 침해·제어 계보 C와 중요 데이터의 분류·이동 계보 D를
> 클라우드 감사 로그에서 독립적으로 재구성한다. C 주체가 D 자산에 읽기·수정·삭제·복사 영향을 준
> 최초 typed intersection을 식별하여 C-only와 D-only 분석을 보완하고, 전체 실행 경로를 변경하지 않는
> 선택 수집 방식의 정확도·조사량·비용·지연 및 재구성 가능성을 평가한다.

## 참고 근거

- [SLEUTH: Real-time Attack Scenario Reconstruction from COTS Audit Data](https://sisl-lab.red.uic.edu/wp-content/uploads/sites/330/2018/07/SLEUTH.pdf)
- [NIST impact 정의](https://csrc.nist.gov/glossary/term/impact)
- [CloudTrail 데이터 이벤트와 advanced selector](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html)
- [CloudTrail 이벤트 필드](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html)
- [CloudTrail log file integrity validation](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html)
- [CISC 논문 제출 안내](https://www.cisc.or.kr/notice/article/1324)
