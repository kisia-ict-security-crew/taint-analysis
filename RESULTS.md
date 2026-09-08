# 실행 시점 C-/D-Taint 프로토타입: 초기 결과

실험일: 2026-09-08  
실행 리전: AWS ap-northeast-2 (Seoul)  
상태: 초기 단일 실행 결과. 반복·비용·일반화 성능 결과가 아니다.

원 논문의 주장과 현재 결과의 대응, 이론 보강 및 개정 평가 설계는
[논문 분석·실험 연계](PAPER_REVIEW_AND_INTEGRATION.md)에 정리했다.

## 초록용 결과 서술

본 연구는 HoneyToken 접촉을 침해 시작점으로 표시하는 C-Taint와 중요 데이터의 흐름을 표시하는 D-Taint를
AWS 실행 경로에서 단조 전파하는 프로토타입을 구현하였다. API Gateway, Lambda reference monitor,
DynamoDB 상태 저장소, S3 객체 태그, STS 위임을 결합하여 CloudTrail 사후 조회 없이 상태를 확정하였다.
실제 AWS 단일 계정에서 정상 쓰기, HoneyToken 접촉 후 2단계 자격증명 위임 및 중요 데이터 복사,
HoneyToken을 우회한 중요 데이터 변환의 세 경로를 실행했다. 생성된 S3 출력 세 개는 각각
`(C,D)=(0,0)`, `(1,1)`, `(0,1)` 태그를 가져 설계한 분류와 일치했다. 이 결과는 실행 시점 label
전파의 실현 가능성을 보이지만, 탐지 성능, 대규모 처리량, 비용 우위, 일반 워크로드 적용성을 입증하지는 않는다.

## 연구 질문과 측정 범위

| 연구 질문 | 이번 측정 |
|---|---|
| RQ1. CloudTrail 사후 분석 없이 C/D label을 실행 경로에서 확정할 수 있는가? | AWS 배포 후 Lambda broker가 DynamoDB와 S3 태그를 갱신하는지 확인 |
| RQ2. HoneyToken 접촉과 중요 데이터 흐름의 교차를 구분할 수 있는가? | B0, S1, S2의 최종 출력 label 비교 |
| RQ3. Taint 상태가 실행 주체와 출력 자산에 남는가? | DynamoDB 상태/edge 개수, S3 출력 태그 확인 |
| RQ4. 운영 성능·비용에 유리한가? | 미측정. 이 초기 실행은 근거가 아님 |

## 구현·배포 범위

배포된 구성은 IAM 인증 API Gateway, Python 3.12 Lambda broker, DynamoDB pay-per-request table,
versioning·암호화·public access block이 설정된 S3 bucket, worker/broker IAM role이다.
Lambda는 Active 상태였고, 배포 후 endpoint와 worker role이 생성됐다.

전파는 broker 요청 안에서 수행한다. HoneyToken을 읽으면 실행 credential의 C가 True가 되고,
D 자산을 읽으면 실행 문맥의 D가 True가 된다. 이후 write/copy 출력에는 문맥의 C/D를 OR join하여
태그와 DynamoDB 상태를 먼저 기록한 뒤 객체를 쓴다. child credential은 server-owned parent를 통해
발급한다. 단순히 C-marked 객체를 읽는 행위는 다른 실행 주체의 C를 만들지 않는다.

이번 계정은 Lambda account concurrency가 10이어서 function reserved concurrency를 사용할 수 없었다.
따라서 broker는 DynamoDB 전역 lease를 획득한 요청만 처리하고, lease를 얻지 못한 요청은 503으로
종료한다. 이는 현재 실험의 순서 보장 방식이며, 처리량 확장 방식은 아니다.

## 실험 시나리오

| ID | 실행 경로 | 기대 label |
|---|---|---|
| B0 | 독립 worker → 일반 `put` | `(C,D)=(0,0)` |
| S1 | HoneyToken `read` → `delegate` 2회 → 중요 객체 `copy` | `(C,D)=(1,1)` |
| S2 | 독립 worker → 중요 객체 `read` → 변환 후 `put` | `(C,D)=(0,1)` |

모든 데이터는 합성 문자열이며, HoneyToken은 실제 자격증명이 아니다. S1과 S2는 서로 다른 worker credential에서 시작했다.
S1의 C는 HoneyToken read에만 근거하며, S2에는 HoneyToken 접촉이 없다.

## 확인된 결과

단일 자동 실행은 broker 요청 7회를 발생시켰다: B0 1회, S1 4회, S2 2회.
실행 뒤 DynamoDB table에는 상태, credential parent, resource, edge, lease를 포함해 17개 항목이 존재했다.
정확한 항목 유형별 수는 이번 결과에서 분해 집계하지 않았다.

| 출력 객체 | 시나리오 | 실제 S3 tag | 판정 |
|---|---|---|---|
| `derived/<run-id>/normal` | B0 | `taint-c=false`, `taint-d=false` | CLEAN |
| `derived/<run-id>/copy` | S1 | `taint-c=true`, `taint-d=true` | C∩D |
| `derived/<run-id>/transformed` | S2 | `taint-c=false`, `taint-d=true` | D-only |

이 결과는 C∩D와 D-only를 구분한다. 즉 HoneyToken 접촉으로 시작한 경로는 중요 데이터 복사에서
교차점이 되고, HoneyToken을 거치지 않은 중요 데이터 변환은 C 없이 D-only로 남았다.
이는 C∩D만으로 모든 중요 데이터 이동을 침해로 단정하지 않는 설계와 일치한다.

### Lambda 실행 시간 관측

CloudWatch Lambda REPORT의 단일 실행 표본 7개에서 Lambda handler duration은 최소 402.19 ms,
중앙값 449.05 ms, 평균 938.50 ms, 최대 3,587.91 ms였다. 첫 호출은 3,587.91 ms였고 init duration은
94.66 ms로 기록됐다. 이 값은 Lambda 내부 실행 시간이며 API Gateway, 네트워크, STS 호출 및
클라이언트 전체 지연을 포함한 end-to-end latency가 아니다. 표본 7개로 p95, 처리량, cold-start 영향,
성능 우위를 주장하지 않는다.

## 논문 본문에 사용할 수 있는 결과 문단

> 실제 AWS 서울 리전의 단일 계정에 실행 시점 Taint broker를 배포하고 세 개의 합성 데이터 경로를 실행하였다. 정상 쓰기는 `taint-c=false`, `taint-d=false`로 유지됐다. HoneyToken을 성공적으로 읽은 worker가 두 번의 위임 후 중요 데이터를 복사한 경로에서는 목적지 객체에 `taint-c=true`, `taint-d=true`가 기록됐다. 반면 HoneyToken과 무관한 worker가 중요 데이터를 읽어 변환·저장한 경로에서는 `taint-c=false`, `taint-d=true`가 기록됐다. 따라서 제안한 prototype은 감사 로그의 사후 상관 없이 HoneyToken 기반 C-Taint와 중요 데이터 기반 D-Taint를 실행 시점에 구분하고, 두 label의 교차점을 S3 출력 자산에서 확인할 수 있었다.

> 단, 이 평가는 단일 계정·단일 실행·64 KiB 이하 합성 S3 객체·단일 전역 lease라는 제한된 조건에서 수행됐다. 측정된 Lambda handler duration 표본은 7개뿐이며, 비용, 처리량, 탐지 precision/recall, 정상 워크로드의 과도 전파율은 평가하지 않았다. 따라서 본 결과는 클라우드 실행 경로에서의 구현 가능성 증거로 해석해야 하며, 기업 인프라 전체에 대한 성능 또는 경제성 주장으로 일반화할 수 없다.

## 논문 결과에 아직 쓰면 안 되는 주장

- 전 자산·전 서비스에 대한 Taint 전파 지원
- 기업 환경에서의 비용 절감 또는 낮은 오버헤드
- 공격 탐지율, 오탐률, precision/recall
- S3 외 Secrets Manager, EKS, EC2/ECS, Lambda invocation, SQS/SNS, DB의 전파 결과
- 직접 S3/STS/DynamoDB 우회 거부의 실제 결과: runner에 검사가 있으나 정제된 runner stdout을 보존하지 않아 이 문서의 결과로 집계하지 않음

## 다음 결과 수집 계획

1. 조건별 30회 이상 반복하고 warm/cold 호출을 분리한다.
2. B0에 정상 read-transform-write와 동시 요청을 포함해 과도 전파율을 측정한다.
3. 직접 API 우회, retry, Lambda timeout, DynamoDB lease 충돌, S3 write 실패를 독립적으로 기록한다.
4. end-to-end latency, DynamoDB/S3/Lambda/API Gateway 비용, 상태·edge 저장량을 baseline과 비교한다.
5. Secrets Manager adapter와 EKS Pod/process adapter를 추가하고, 자산별 강제 경계와 미지원 범위를 분리해 보고한다.
6. 지뢰 수 N을 0, 1, 10, 100, 1000으로 늘려 공유 처리기의 유휴 비용과 지뢰 1개당 registry 비용을 분리한다.
7. Boolean 대신 C/D seed 원인 집합과 최초 교차 edge를 저장해 여러 캠페인의 설명 가능성을 검증한다.

연구 의미론·자산별 확장 범위는 [RESEARCH_REDESIGN.md](RESEARCH_REDESIGN.md)를, 배포 절차와 구현 제약은
[runtime README](infrastructure/runtime/README.md)를 따른다.
