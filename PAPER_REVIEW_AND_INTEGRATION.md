# 「클라우드 지뢰형 탐지 기술과 비가역적 Taint 기반 침해 영향 추적 구조 제안」 분석 및 실험 연계

검토일: 2026-09-08  
원문 범위: 3쪽, 서론·구조 제안·Taint 정의·평가 계획·향후 연구·참고문헌. 논문 안에는 완결된 실험 결과가 없다.

## 1. 논문의 정확한 주장

논문은 자격증명 탈취 이후 공격자가 정상 인증 수단과 API를 사용하면 단순 이상행위 탐지만으로 침해를
구분하기 어렵다는 문제에서 출발한다. 상시 실행되는 가상 시스템·컨테이너·미끼 네트워크는 접촉이 없어도
운영 자원을 유지하지만, HoneyToken 같은 경량 지뢰는 접촉 시점에 증거를 만들 수 있다는 관찰을 사용한다.

제안 구조의 중심은 특정 HoneyToken 하나가 아니다. 다음 네 요소를 하나의 체계로 묶는 것이다.

1. 자격증명·URL·DNS·데이터·외부 반출 지뢰를 등록하는 지뢰 마켓플레이스와 공통 명세.
2. CSP별 인증·이벤트 형식 차이를 공통 이벤트로 바꾸는 CSP 연동 모듈.
3. 같은 종류의 다수 지뢰가 공유하는 공통 처리기와 저장소.
4. 지뢰 접촉의 C-Taint와 중요 데이터의 D-Taint를 비가역적으로 누적하고 교차점을 찾는 처리 영역.

지뢰 추가는 새 서버나 처리기의 상시 실행이 아니라 고유 식별자, 정책, 작은 객체의 등록이어야 한다.
논문이 제안한 비용 평가는 공격이 없을 때의 기본 비용, 지뢰 1개 추가 비용, 접촉 1회 처리 비용이다.
향후 AWS와 Naver Cloud에서 자격증명·URL·데이터 지뢰를 구현하고 CSP 이식성과 비용 증가를 검증한다고 적었다.

따라서 이 논문은 **아키텍처와 연구 가설을 제안한 short paper**다. 저비용, 이식성,
영향 범위 축소는 측정 결과가 아니라 검증 예정 목표다.

## 2. 이론 모델 보강

원문의 `T(t+1) ⊇ T(t)`, `T(t+1)=T(t)∪E`는 방향은 맞지만 객체, 증거, 인과관계가 정의되지 않았다.
다음처럼 형식화하면 구현과 평가가 연결된다.

- 시간 t까지의 provenance graph를 `G_t=(V,E_t)`로 둔다. V는 credential instance, execution context,
  versioned resource, message 등이며 edge는 read, write, delegate, execute, send 같은 typed relation이다.
- 각 엔터티 v의 label은 `L_t(v)=(C_t(v),D_t(v))`이고 각 성분은 Boolean보다 **원인 seed ID의 집합**으로 둔다.
- join은 집합 합집합이다: `L_{t+1}(v)=L_t(v) ⊔ Δ_t(v)`. 따라서 `L_t(v) ⊆ L_{t+1}(v)`이다.
- C는 공격자 영향 또는 제어권 전파, D는 중요 데이터의 정보 흐름이다. 두 label은 같은 규칙으로 전파하지 않는다.
- 교차점은 단순히 같은 객체에 두 Boolean이 있는 경우만이 아니다. `C_t(v)≠∅ ∧ D_t(v)≠∅`인
  이벤트/엔터티 또는 C 원인과 D 원인이 typed causal path로 만나는 최초 지점이다.
- 여러 HoneyToken과 중요 데이터가 있을 때 `X(v)={(c,d) | c∈C(v), d∈D(v)}`를 보존해야
  서로 다른 침해 캠페인과 데이터 계보를 구분할 수 있다.

현재 runtime의 Boolean C/D는 이 모델의 축약판이다. feasibility에는 충분하지만 원인 집합과 최초 교차점을
복원하지 못한다. 다음 구현 단계에서 `c_sources`, `d_sources`, `first_intersection_edge`를 추가해야 한다.

### 신뢰도와 전파 규칙

사용자 정의 정책만 강조하면 동일 사건이 설정에 따라 임의 판정되는 문제가 생긴다. 공통 명세에는 규칙뿐 아니라
근거 강도를 포함해야 한다.

| 근거 등급 | 의미 | 예시 |
|---|---|---|
| E0 Seed | 관리자가 등록한 시작점 | HoneyToken, 중요 데이터 version |
| E1 Exact | 실행 경로가 직접 인증한 전파 | broker가 반환 전 상태 기록, child credential 직접 발급 |
| E2 Derived | 어댑터가 보수적으로 계산한 전파 | D를 읽은 세션의 후속 출력 |
| E3 Correlated | 시간·IP·로그 상관에 기반한 후보 | CloudTrail 사후 보조 분석 |

C∩D 결과에는 seed ID, typed path, 근거 등급, 발생 시점, adapter version을 함께 기록한다.

## 3. 관련 연구와의 관계

SLEUTH는 COTS audit data를 platform-neutral dependency graph로 바꾸고 tag를 이용해 source identification,
impact analysis, compact attack graph를 실시간 수행한다. 현재 연구는 HoneyToken을 고신뢰 seed로 사용하고
관리형 클라우드 API의 실행 경로에서 label을 먼저 확정한다. CloudTrail legacy 분석은 SLEUTH 계열의
스트리밍/사후 provenance baseline으로 사용할 수 있다.

RTAG는 host별 DIFT tag를 네트워크 패킷에 실어 cross-host flow를 연결하고 record/replay로 tag dependency와
분석을 분리해 lazy synchronization한다. 현재 연구에는 두 가지 시사점이 있다.

- CSP/host 경계를 넘는 label은 임의 HTTP header가 아니라 인증된 context여야 한다.
- 모든 상세 tag를 매 요청에서 동기화하지 않고 source ID와 dependency를 지연 결합하면 비용을 줄일 수 있다.

RTAG가 보고한 bandwidth overhead와 메모리·분석시간 감소율은 RTAG 구현 결과다. 현재 runtime의 성능
근거로 재사용할 수 없다. 같은 지표를 본 시스템에서 별도로 측정해야 한다.

Zhang과 Thing의 deception survey는 honeypot, HoneyToken, moving-target defense를 공격 단계와
network/system/software/data layer로 분류하고, 통합 deception과 운영 비용 정량화를 향후 방향으로 제시한다.
지뢰 명세에 `attack_stage`, `deception_layer`, `trigger`, `cost_class`를 추가하면 직접 연결할 수 있다.

## 4. 현재 실험과의 대응

| 논문 구성요소 | 현재 상태 | 논문에 쓸 수 있는 해석 |
|---|---|---|
| 공통 처리기 | AWS API Gateway + Lambda broker 1개 | 두 seed와 모든 실험 요청이 동일 처리기를 사용함 |
| 비가역 Taint | DynamoDB에서 False→True join | 단위 테스트로 단조성 확인, 장기·장애 조건은 추가 필요 |
| 데이터 지뢰 | S3 HoneyToken과 중요 데이터 | AWS 한 CSP, 합성 객체 두 개 |
| C/D 교차 | S1 output `(1,1)` | 실행 시점 교차 feasibility |
| D-only | S2 output `(0,1)` | HoneyToken 우회 흐름을 공격 확정으로 과장하지 않음 |
| 정상 기준선 | B0 output `(0,0)` | 단일 정상 쓰기에서 불필요한 Taint 없음 |
| 공통 지뢰 명세 | `cloud-mine/v1alpha1` schema와 DynamoDB registry | 로컬 구현·테스트 완료, AWS 재배포 전 |
| CSP 연동 | AWS S3/STS만 구현 | 다중 CSP 이식성 근거 없음 |
| 비용 효율성 | 미측정 | 논문의 핵심 가설이 아직 열려 있음 |
| 영향 범위 축소 | 미측정 | 전체 이벤트 대비 C∩D 후보 감소율을 측정해야 함 |

2026-09-08 초기 AWS 실행에서 B0, S1, S2의 S3 출력 태그는 각각 `(0,0)`, `(1,1)`, `(0,1)`이었다.
이는 label 구분과 교차 생성의 동작 예시다. 조건당 1회이므로 detection rate나 false-positive rate가 아니다.

## 5. 구현에 반영한 수정

- `cloud-mine.schema.json`에 `spec_version`, `mine_id`, `kind`, `resource`, `trigger`, C/D 발생 정책을 정의했다.
- Terraform이 HoneyToken과 중요 데이터 지뢰를 `mine:<resource>` DynamoDB 항목으로 등록한다.
- broker는 파일명으로 seed를 하드코딩하지 않고 registry 정책을 읽는다.
- 두 지뢰는 같은 API Gateway, Lambda, DynamoDB table을 공유한다.
- 같은 S3 kind의 지뢰 인스턴스 증가는 처리기 복제를 요구하지 않는다. 새 kind는 adapter 구현이 필요하다.

현재 registry 변경은 로컬 단위 테스트 17개와 Terraform validate를 통과했다. AWS에는 아직 재배포하지 않았으므로
기존 AWS 결과를 registry 구현의 실측 결과로 사용하면 안 된다.

## 6. 논문에서 반드시 수정할 부분

1. 참고문헌 [1]과 [3], [2]와 [4]는 각각 같은 논문이 중복되어 있다. 하나씩만 남긴다.
2. 수식은 `T_t(v)`, `E_t`, `⊔`의 정의와 전파 대상 v를 명시한다. PDF의 `tt`, `EE`, 중복 표기는 고친다.
3. “비가역적”은 삭제 불가능하다는 뜻이 아니라 같은 엔터티 생애에서 label이 단조 증가한다는 뜻으로 제한한다.
4. C-Taint의 침해 확인과 침해 의심을 구분하고 HoneyToken 배타성 가정과 관리자 시험 접촉을 명시한다.
5. D-Taint의 객체 분류와 실제 정보 의존을 나눈다. session-level read→write는 보수적 파생이지 byte-level DIFT가 아니다.
6. “동일 객체 또는 인과관계상 교차”를 typed graph의 최초 교차점으로 정의한다.
7. 공통 이벤트 처리와 실행 시점 reference monitor를 분리한다. 전자는 E3 감사 근거, 후자는 E1 전파 근거다.
8. 비용·이식성·낮은 오버헤드는 결과 전에는 목표 또는 가설로 쓴다.
9. 위협 모델, 신뢰 경계, 우회 가능성, 장애 시 fail-closed/fail-open 정책을 추가한다.
10. 제목과 초록에 prototype 또는 AWS case study 범위를 표시한다.

## 7. 신뢰도를 높이는 평가 설계

### H1: 지뢰 수와 유휴 비용 분리

`N={0,1,10,100,1000}`개 지뢰를 같은 처리기에 등록하고 각 조건을 최소 24시간, 가능하면 7일 유지한다.

`Cost(N,M,E)=Cost_shared_idle + N·Cost_registry + M·Cost_contact + E·Cost_evidence`

M은 접촉 수, E는 edge 수다. H1은 N 증가가 Lambda 상시 실행 수를 늘리지 않고 registry의 한계비용만
늘린다는 것이다. 저장 byte, Terraform apply 시간, inventory query 비용도 측정한다.

### H2: 접촉 비례 처리 비용

고정 N에서 M을 0, 1, 10, 100, 1000으로 바꾸고 API Gateway request, Lambda duration/GB-s,
DynamoDB R/W request, S3 request, retry와 throttling을 측정한다. Cost and Usage Report와 공식 단가 계산을 대조한다.

### H3: 조사 범위 감소

정답 공격 graph가 있는 반복 시나리오에서 다음을 보고한다.

- `1 - |C∩D review candidates| / |all security-relevant events|`
- 최초 HoneyToken 접촉부터 최초 중요 데이터 교차까지의 지연
- true causal edge recall, extraneous edge ratio, 최초 교차점 precision
- B0 정상 workload의 C/D 과도 전파율

legacy CloudTrail analyzer, C-only, D-only, C∩D를 같은 행위에서 비교한다. 후보 수와 true path recall을 함께 본다.

### H4: CSP 이식성

동일한 provider-neutral mine spec과 시나리오를 AWS와 Naver Cloud adapter에 적용한다. 공통 필드 충족률,
provider-specific 필드 수, adapter 코드량, 배포 시간, 정책 의미 차이를 측정한다. 두 CSP 결과는
“multi-cloud generality”보다 “two-provider portability feasibility”로 표현한다.

### H5: 실패와 우회 내성

직접 S3 접근, forged actor/C/D payload, registry 변조, DynamoDB 장애, lease 충돌, Lambda timeout,
중복 요청, child 발급 직후 부모 오염, output write 실패를 시험한다. 데이터나 credential이 label 확정 전에
반환되는지 확인하고 미계측 경계를 coverage 분모에 포함한다.

## 8. 논문에 추가할 수 있는 결과 문장

> 제안 구조의 AWS feasibility를 확인하기 위해 두 개의 S3 지뢰와 하나의 공유 실행 시점 처리기를 구성하였다. 단일 합성 실행에서 정상 쓰기, HoneyToken 접촉 후 위임 및 중요 데이터 복사, HoneyToken 비접촉 중요 데이터 변환은 각각 `(C,D)=(0,0)`, `(1,1)`, `(0,1)`의 출력 label을 생성하였다. 이 결과는 한 AWS 계정의 제한된 S3/STS 경로에서 공통 처리기를 이용한 C/D 구분과 교차 생성이 가능함을 보인다. 지뢰 수 증가 비용, 반복 정확도, 다중 CSP 이식성은 후속 평가 대상으로 남는다.

“저비용임을 입증했다”, “침해 범위를 획기적으로 줄였다”, “다중 클라우드에 적용됐다”는 문장은 아직 사용할 수 없다.

## 9. 개정 논문 권장 목차

1. 문제 정의와 기여: 공유 지뢰 처리, 단조 C/D label, 최초 교차점.
2. 관련 연구: deception taxonomy, SLEUTH provenance, RTAG cross-host tag, DIFC/reference monitor.
3. 위협 모델과 신뢰 경계.
4. 공통 지뢰 명세 및 CSP adapter 계약.
5. Taint lattice, typed propagation, evidence confidence, intersection 정의.
6. AWS prototype 구현.
7. 평가: H1-H5, baseline, 데이터셋·반복·통계 방법.
8. 결과와 한계.
9. 다중 CSP 확장과 결론.

## 참고 근거

- M. N. Hossain et al., “SLEUTH: Real-time Attack Scenario Reconstruction from COTS Audit Data,” USENIX Security 2017.
- Y. Ji et al., “Enabling Refinable Cross-Host Attack Investigation with Efficient Data Flow Tagging and Tracking,” USENIX Security 2018.
- L. Zhang and V. L. L. Thing, “Three Decades of Deception Techniques in Active Cyber Defense - Retrospect and Outlook,” Computers & Security 106, 2021, Article 102288.
- M. Krohn et al., “Information Flow Control for Standard OS Abstractions,” SOSP 2007.
- N. Zeldovich et al., “Securing Distributed Systems with Information Flow Control,” NSDI 2008.

원문 참고문헌의 중복 두 항목은 통합했다. 현재 runtime의 직접 근거와 외부 연구의 결과 수치는 분리해 인용한다.
