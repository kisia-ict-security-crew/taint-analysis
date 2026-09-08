# 실행 시점 C-/D-Taint 연구 재설계

작성: 2026-09-08. 상태: 연구 설계 수정, AWS 실행 경로 배포 및 최초 단일 실행 완료.
논문 연계 분석과 개정 평가 설계는 [PAPER_REVIEW_AND_INTEGRATION.md](PAPER_REVIEW_AND_INTEGRATION.md)를 따른다.

## 1. 목적과 기존 오류

명확한 HoneyToken 접촉을 침해 시작점으로 삼아 침입자의 발자국을 C-Taint로 남기고,
중요 데이터의 D-Taint와 교차하는 확인 지점을 찾아 조사해야 할 확산 경로와 확인 지점 수를 줄인다.
전파는 단조 증가하며, 낮은 실행 오버헤드와 총비용 우위는 검증해야 할 연구 가설이다.
탐지와 전파를 구현했다고 실제 침입 자체가 줄어드는 것은 아니다. 차단 효과는 별도 실험 대상이다.

기존의 CloudTrail → 로컬 CEM → 집합 전파는 이 목적의 실행 시스템이 아니다.
Lambda로 분석기를 옮기거나 사후 객체 태그를 붙이는 것으로는 이 오류가 해결되지 않는다.
기존 `infrastructure/aws/analysis`는 감사 증거 대조와 기준선으로만 유지한다.
기존 B0/S1-a/S2 실행기는 legacy 실험이며 새 중개 경로를 검증하지 않는다.

핵심 수정은 작업의 허용된 실행 경로에 신뢰할 수 있는 전파 지점을 두고,
데이터나 자격증명을 내보내기 전에 상태를 확정하는 것이다. CloudTrail은 전제 입력이 아니다.

## 2. 의미론과 위협 모델

엔터티 e의 상태를 L(e)=(C(e),D(e))로 정의한다. 기본 표현은 두 Boolean의 join(OR)이다.
같은 엔터티 생애 동안 False→True만 허용한다. 만료·종료는 사용 가능성의 종료이며 기록 삭제가 아니다.
자원 교체에는 새 세대/버전 식별자가 필요하다. clean reset API는 제공하지 않는다.

장기 목표는 원인 seed 집합과 typed edge를 함께 보존하는 것이다. 현재 코드는 Boolean과 edge,
위임 parent만 구현하므로 여러 독립 침해 캠페인을 분리하는 기능은 아직 없다.
TTL, 태그 개수 제한, 원인 집합 overflow로 근거를 조용히 버리는 방식은 허용하지 않는다.

전파 규칙:

1. **HONEY_CONTACT:** 등록된 미끼 데이터의 성공적 취득에서 실행 주체의 C를 올린다.
   현재는 S3 미끼 한 종류다. 실제 Credential honeytoken 사용 감지는 별도 신뢰 경로가 필요하다.
   정상 업무가 미끼에 접근하지 않는다는 배치 가정을 검증하며, 관리자의 시험 접촉도 추적한다.
2. **CONTROL_DELEGATE:** C 주체가 발급한 자식 실행 권한에 C를 상속한다. D 실행 문맥도 상속한다.
   parent→child 관계를 유지하여 자식 발급 후 부모가 오염되어도 자식의 다음 작업에서 반영한다.
   현재 구현은 부모와 자식이 동일 신뢰 경계에 있다는 보수적 가정이다.
3. **DATA_READ:** D 객체를 읽은 실행 문맥에 D를 누적한다.
4. **DATA_WRITE:** 실행 문맥의 D를 출력 객체에 상속한다. 가공·재인코딩도 문맥 범위에서는 보존한다.
   상관없는 출력도 오염될 수 있으므로 정밀한 데이터 의존 증명으로 표현하지 않는다.
5. **C_FOOTPRINT:** C 주체가 접근·작성한 객체에 발자국을 남긴다. 단순한 접촉은 손상 확정이 아니다.
6. **CONTROL_EXECUTE:** C 영향을 받은 코드/명령의 실행은 새 실행 문맥의 C 후보가 된다.
   단순 파일 읽기와 구분한다. 현재 AWS broker에는 실행 어댑터가 없으므로 이 규칙은 미구현이다.
7. **INTERSECTION:** C 실행 주체가 D 데이터에 접근하거나 D 출력을 만들 때 온라인으로 표시한다.
   HoneyToken 자체의 교차와 별도 중요 데이터의 교차를 보고서에서 분리한다.

각종 ARN, IP, 역할명, 동일 클러스터 소속만으로 C를 전파하지 않는다.
IAM Role/ServiceAccount는 공유 정책 주체다. 실제 추적 단위는 credential instance,
Pod UID, container ID, process start identity, object version, message ID 등이다.
Pod의 Kubernetes scheduling `taint`는 본 연구의 보안 Taint와 별개다.

공격자는 실험 worker 세션과 전달받은 데이터·자격증명을 제어할 수 있다.
broker 실행 역할, IAM 관리자, DynamoDB 관리자, 노드 커널/호스트 관리자는 신뢰 경계 안에 있다.
이 권한이 침해되면 보장을 유지한다고 주장하지 않는다.
새 독립 자격증명으로 재진입한 공격자를 기존 C와 연결할 근거가 없으면 자동 연계하지 않는다.
미끼 우회 공격은 D-only로 남을 수 있다. C∩D는 모든 침해를 포괄하지 않는다.

## 3. 기술 선택 근거

| 기술/연구 | 채택할 원리 | 적용 범위와 제약 |
|---|---|---|
| [Flume / SOSP 2007](https://pdos.csail.mit.edu/~yipal/papers/flume-sosp07.pdf) | 실행 경로의 reference monitor와 실행 문맥 label | 중개를 우회하지 못하게 해야 함. 논문의 성능을 본 시스템 성능으로 인용하지 않음 |
| [DStar / NSDI 2008](https://www.usenix.org/conference/nsdi-08/securing-distributed-systems-information-flow-control) | 분산 경계에서 인증된 문맥과 호스트 보호를 결합 | 임의 HTTP header를 신뢰하지 않음. 서비스 간 프로토콜은 후속 구현 |
| [CamFlow](https://camflow.org/) | OS의 파일·프로세스·통신 관계와 선택적 추적 | 전체 provenance 수집을 그대로 도입하면 비용 목적과 충돌 가능. 선택 범위를 측정 |
| [Linux BPF LSM](https://docs.kernel.org/bpf/prog_lsm.html) | 호스트가 관리 가능한 구간의 실행 시점 hook | 지원 커널·LSM 설정과 권한 필요. managed service 내부에는 설치할 수 없음 |
| [AWS STS session tags](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_session-tags.html) | 발급 당시의 초기 label과 transitive tag 후보 | 기존 세션의 동적 오염을 태그만으로 관리할 수 없음. 현재는 server-owned parent/state 사용 |
| [S3 object tags](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-tagging.html) | 출력 생성 시 label 가시화 | 10개 제한과 교체/복사 정책 때문에 원인 그래프 저장소로 사용하지 않음 |
| [Kubernetes admission](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/) | Pod 생성 시 계측·정책 강제 | 컨테이너 내부 파일 읽기·프로세스 실행까지 admission이 관측하지는 못함 |
| [API Gateway IAM proxy context](https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-lambda-proxy-integrations.html) | 인증된 호출 자격증명에서 실행 엔터티 식별 | 요청 body의 actor/C/D를 신뢰하지 않음. 실제 context 필드 수신은 배포 검증 게이트 |

SLEUTH와 RTAG를 포함한 현재 논문과의 상세 차이는 연계 분석 문서에 기록한다.
현재 선정은 이 문헌·공식 문서와 프로젝트 요구사항을 바탕으로 한 설계 판단이다.
체계적 문헌조사 전체나 최적성 증명을 완료했다는 뜻은 아니다.
가장 타당한 조합은 **관리형 API의 강제 중개 + 워크로드의 선택적 실행 계측 + 단조 상태의 인증된 전달**이다.
어떤 단일 AWS 태그 기능도 이 전체 조합을 대신하지 않는다.

## 4. 자산별 적용 계약과 구현 범위

| 자산/경계 | 강제 개입 지점 | label 부착/전달 | 현재 상태 |
|---|---|---|---|
| AWS S3 미끼 읽기 | broker가 데이터를 반환하기 전 | 자격증명 C/D를 DynamoDB에 기록 | 구현 |
| S3 read → transform → put | 읽기/출력 API 중개 | 세션 D 누적, 출력에 C/D 태그와 상태 | 구현, 세션 단위 보수적 전파 |
| S3 복사 | broker가 source를 읽고 destination을 생성 | 상태 선기록, 새 객체 태그 | 구현, 64 KiB·새 key 한정, native CopyObject 아님 |
| STS 역할 위임 | broker만 자식 worker 자격증명 발급 | server-owned parent, credential fingerprint | 구현, 동일 역할 인스턴스 체인·최대 깊이 제한 |
| Secrets Manager/SSM | 반환을 중개하는 서비스 adapter | secret version → 실행 문맥 | 설계만, 기존 EventBridge 경보는 대체물이 아님 |
| Lambda 실행 | invoke wrapper/extension + 직접 invoke 제한 | invocation ID별 서명 문맥 | 미구현. warm process 간 label 공유 금지 |
| EKS Pod/컨테이너 | admission + 노드 agent | Pod UID/container ID 상태, 보호 annotation | 미구현. annotation만으로 커널 흐름 추적 불가 |
| 프로세스·파일·소켓 | fork/exec/read/write/IPC 계측 | PID+시작시간, inode+세대의 label map | 미구현. eBPF/LSM 검증용 별도 Linux 실험 필요 |
| EC2/ECS | host agent 또는 강제 egress broker | task/process 실행 문맥 | 미구현. Fargate에서 임의 커널 hook 가정 금지 |
| SQS/SNS/EventBridge 메시지 | send/receive 양측 wrapper + IAM 제한 | message별 인증 문맥, payload lineage | 미구현. 재시도/배치 혼합/위조 방지 필요 |
| RDS/DB | connection proxy 또는 DB extension | connection/transaction/row version label | 미구현. SQL 의존과 connection pool 혼합 고려 |
| HTTP/gRPC 서비스 호출 | 신뢰 proxy/SDK 양측, 직접 우회 차단 | 인증된 request 문맥 | 미구현. 범용 서비스 역할 전체 오염 금지 |
| 이미지/아티팩트 | build/publish/deploy gate | digest와 실행 인스턴스 연결 | 미구현. 다운로드와 실행은 다른 edge |
| 외부 계정/인터넷 | egress gate | C∩D sink 판정, 양측 신뢰 계약 | 미구현. 외부 비협조 시스템까지 자동 전파 보장 불가 |

"모든 자산"은 동일한 label 모델과 adapter 계약을 적용할 연구 범위다.
모든 자산의 내부 동작을 이미 추적한다거나, 설치 지점 없이 자동 지원한다고 주장하지 않는다.
새 어댑터는 identity 인증, 개입 시점, 우회 제한, join, 교차 판정, 실패 처리, 비용 측정을 통과해야 한다.

## 5. 이번에 구현한 AWS 실행 구조

`infrastructure/runtime/`는 기존 AWS 로그 수집 환경과 독립적인 Terraform root다.
CloudTrail, Athena, ECS cluster, NAT Gateway를 필수 구성으로 만들지 않는다.

```text
IAM 인증 worker 요청
  → API Gateway AWS_IAM
  → Lambda broker (DynamoDB 전역 lease를 얻은 요청 1개 처리)
      → DynamoDB: credential/parent/resource/edge
      → S3: 합성 seed와 label이 붙은 derived 객체
      → STS: broker만 worker 자식 자격증명 발급
  → 상태 확정 후 데이터/자격증명/교차 판정 반환
```

worker에는 연구 API 호출만 허용하고 다른 AWS 작업은 명시적 Deny한다.
기존 legacy ActorA/PivotB/PivotC를 재사용하지 않는다. 직접 S3 및 STS 접근이 가능한 이전 실험과 구분한다.
API requestContext의 인증된 AccessKey ID를 SHA-256 fingerprint로 바꿔 상태 key로 사용한다.
요청자가 actor, parent, c, d를 보내도 전파 근거로 사용하지 않는다.
전파 엔진은 CloudTrail 조회를 전혀 하지 않는다. client는 서명 요청만 보내며 상태를 판정하지 않는다.

S3 미끼는 실제 자격증명이 아닌 합성 데이터다. 성공적인 fetch 이후 actor label을 확정하고 반환한다.
객체 출력은 destination을 조건부 예약하고 label을 쓴 다음 실제 데이터를 기록한다.
상태 저장 실패 시 읽은 미끼나 신규 credential을 클라이언트에게 내보내지 않는다.
S3 작업과 DynamoDB는 하나의 트랜잭션이 아니므로 실패 시 예약/label이 남을 수 있다.
이것은 확인된 성공 edge와 구분해야 하는 보수적인 잔여 상태다. 실패한 목적지 key는 재사용하지 않는다.
응답이 유실된 작업은 S3에 이미 존재할 수 있다. exactly-once를 주장하지 않는다.

현재 edge는 성공한 API 처리 시 저장하며 응답 반환 전 기록한다. 저장 실패 시 503이다.
호출별 UUID edge라서 read 재시도는 여러 edge를 남길 수 있다. 중복 제거·원인 집합 압축은 후속 단계다.
현재 교차점은 응답과 DynamoDB edge의 `intersection`으로 제공한다. 별도 실시간 알림 subscriber는 미구현이다.

## 6. 단조성과 정밀도·병렬성

현재 label은 C/D Boolean, strong read, True만 쓰는 update로 관리한다.
동시 실행으로 read-before-write 시점이 엇갈리지 않게 DynamoDB 전역 lease로 요청을 직렬화한다.
lease를 얻지 못한 호출은 503으로 종료한다. 멀티 region 공유와 높은 처리량은 현재 지원하지 않는다.
이는 검증 가능한 초기 구현이지 기업 처리량에 적합하다는 주장이 아니다.

부모 상태는 최대 16개 엔터티까지 따라 읽는다. 캐시를 사용하지 않아 부모의 나중 오염이
자식의 다음 요청에 반영된다. 만료 credential의 상태를 삭제하면 이 연결이 끊기므로 TTL은 없다.
자식이 이미 수행한 과거 작업은 부모의 나중 오염으로 소급 변경하지 않는다.

다음 확장에서는 실행 문맥별 shard와 원자적 join, 경계별 epoch/barrier를 검증한다.
단조 상태라도 오래된 clean cache로 출력하면 false negative가 생긴다. 단순 TTL 캐시는 해결책이 아니다.
trusted context별 cache와 변경 전파가 완료되기 전 release를 막는 프로토콜이 필요하다.

세션 단위 D 누적은 여러 요청을 공유하는 서비스에서 과도하게 퍼질 수 있다.
프로세스 단위도 같은 문제가 있다. invocation/request/transaction 단위의 격리 비용과
과도 전파 감소를 비교해서 서비스별 기본 단위를 정한다.

## 7. 비용과 오버헤드 평가 계획

저비용은 목표이며 현재 실측 결과가 아니다. API Gateway/Lambda/DynamoDB 중개가
기존 직접 S3 작업보다 느리고 비쌀 수 있다. 작은 실험에서만 경제적이어도 기업 우위라고 일반화하지 않는다.

baseline은 (A) 직접 실행, (B) 동일 broker에서 label 작업을 제외한 실험 전용 baseline,
(C) 현재 inline taint, (D) 기존 CloudTrail 사후 분석이다. B의 우회 기능을 운영 broker에 넣지 않는다.
A 대비 전체 도입 비용, B 대비 taint 고유 비용, D 대비 판정 지연·조사량을 각각 비교한다.

측정 항목:

- p50/p95/p99 추가 지연, 초당 처리량, Lambda cold/warm 차이, throttling/오류율
- CPU/메모리(후속 node agent), 라벨 상태·edge byte, 경로별 DynamoDB read/write 수
- 요청당·전파 edge당 비용, 월간 전체 비용(상태 보존/PITR/전송/감사 비용 포함)
- 최초 HoneyToken 반환 시점과 C 확정 순서, 중요 데이터 출력 시점과 D 확정 순서
- 확인해야 할 전체 행위 수 대비 C∩D 후보 수, 최초 중요 데이터 교차까지 시간
- 제어권 edge/데이터 lineage/교차점별 precision/recall 및 과도 전파율
- 계측 가능한 전체 경계 중 실제 강제 경계 비율; 미지원 경계를 분모에서 숨기지 않음

인프라가 거의 유휴일 때, 정상 고부하일 때, 공격 흐름이 많을 때를 나눠 측정한다.
반복 횟수는 우선 조건당 30회 warm 실행과 별도 cold 샘플을 계획하고 분산을 보고 보강한다.
이는 통계적 충분성을 보장하는 숫자가 아니다. 작업량, payload 크기, region, 가격 조회일을 고정한다.
금전적 우위나 "획기적 감소"는 사전 정의한 비교 결과가 나오기 전에는 결론에 쓰지 않는다.

최적화 순서는 (1) 상태가 이미 True일 때 중복 update 억제(구현),
(2) 변경 시점/최초 교차점 중심 evidence 압축(미구현), (3) 실행 문맥별 안전한 분산 cache(미구현),
(4) 대용량 데이터 payload를 broker에서 복사하지 않는 trusted endpoint adapter(미구현)다.

## 8. 재실행 계획과 게이트

G0 로컬: 단조성, parent 전파, independent session, read-transform-write,
실패 시 미반환, overwrite 제한, C footprint와 control 구분을 테스트한다.

G1 AWS 최소 배포: runtime root를 배포하고 정상 AWS_IAM context 수신, CloudTrail 입력 없이
S1/S2 완료, 출력 태그와 상태를 확인했다. worker 직접 S3 우회 거부는 runner에 구현됐지만 정제된
stdout이 보존되지 않아 결과 보고서의 확정 결과에서는 제외했다.

G2 온라인 실험: B0 clean write, S1 honey→delegate→delegate→read/copy,
S2 critical read→transform→put(D-only), 발급 후 부모 오염, 재시도/타임아웃/장애,
동일 역할의 독립 세션, 병렬 요청, 직접 API 우회, 태그 삭제 시도를 측정한다.
`run_experiment.py`는 B0/S1/S2와 직접 S3 거부를 자동화한다. 나머지는 후속 통합 실험이다.

G3 워크로드 확장: EKS 실험 namespace에 admission 및 Linux node hook를 구현하고
fork/exec/file/IPC/HTTP를 하나씩 검증한다. 각 경계의 직접 우회 실패를 확인한 뒤 coverage를 올린다.
Pod label만 있는 데모를 컨테이너 내부 추적으로 보고하지 않는다.

G4 메시지·함수·DB: send/receive, invocation, transaction 단위 어댑터와
pool/batch 혼합 방지 및 신뢰 문맥 인증을 구현한다. cross-account는 양측 신뢰 계약 후 추가한다.

G5 비용·정확도 평가: baseline과 동일 데이터·행위·정답지를 사용한다.
과도 전파와 미관측 경계를 공개한 상태에서 조사량 감소와 운영비를 보고한다.

## 9. 이행과 기존 자료의 지위

- 새 목적·규칙의 기준 문서: 이 파일.
- 새 실행 구현·배포 안내: `infrastructure/runtime/README.md`.
- 기존 AWS 인프라: legacy baseline. 실제 계정 리소스를 확인하지 않고 destroy하지 않는다.
- 기존 `DECISIONS.md`, `THEORY_TODO.md`, `RUNBOOK.md`, `STUDY.md`: 역사 자료로 표기하고 새 설계로 연결한다.
- 기존 단위 테스트의 PASS는 새 runtime 또는 실제 AWS 배포의 PASS가 아니다.
- 기존 문서의 "실물 로그 확인/비교 완료"는 이 저장소에 근거 산출물이 없어 독립 검증되지 않았다.

현재 미완료 항목은 AWS 배포·실측, node/Pod/DB/message 어댑터, 다중 원인 추적,
처리량 확장, 대용량 객체, 별도 교차점 알림이다. 실제 기업 적용 완료로 표현하지 않는다.
