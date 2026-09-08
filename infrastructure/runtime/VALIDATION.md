# 구현 검증 기록

검증일: 2026-09-08. 로컬 검증과 최초 AWS 실행의 범위를 분리해 기록한다.

| 검사 | 결과 | 의미 |
|---|---|---|
| runtime unittest 17개 | PASS | 상태 join, 위임, registry 정책, D 가공 출력, 인증 거부, lease 직렬화, 장애 처리의 fake-service 단위 검증 |
| legacy analyzer unittest 4개 | PASS | 기존 기준선의 회귀 없음 |
| Terraform init -backend=false | PASS | provider 설치·lock 생성, AWS 리소스 생성 없음 |
| Terraform validate | PASS | 구성 및 provider schema 유효성 |
| Terraform fmt | 적용 | 코드 형식 정리 |
| git diff --check | PASS | 추적 파일 패치의 공백 오류 없음 |

단위 검증만으로 IAM 평가, Gateway 인증 context, Lambda 호출, STS 발급,
DynamoDB 서비스 동작, S3 객체 태그, API 응답 지연을 증명하지 않는다.

2026-09-08에 사용자 계정에서 apply를 시도했고 Lambda reserved concurrency 설정 단계에서 중단됐다.
해당 계정의 `ConcurrentExecutions=10`, `UnreservedConcurrentExecutions=10`이어서 AWS가 1개 예약을
허용하지 않았다. 이후 runtime은 DynamoDB 전역 lease로 직렬화하도록 변경해 AWS에 배포했고,
B0/S1/S2 단일 통합 실행에서 `(0,0)`, `(1,1)`, `(0,1)` S3 태그를 확인했다. 상세 결과는
`RESULTS.md`에 있다.

논문 연계 후 `cloud-mine/v1alpha1` schema와 DynamoDB mine registry를 추가하고 broker의 seed 파일명
하드코딩을 제거했다. 이 변경은 runtime unittest 17개와 Terraform validate를 통과했으나 AWS 재배포 전이다.

핵심 테스트:

- 네 가지 초기 C/D 상태와 모든 join 조합의 단조성.
- 미끼 반환 전 C/D 상태, 독립 세션 분리.
- 위임 후 부모 오염의 자식 다음 요청 반영.
- D-only read→가공 데이터 put 및 출력 태그.
- C 접촉 흔적을 읽었다는 이유만으로 control C를 전파하지 않음.
- 상태 장애 시 HoneyToken 반환 중단.
- 출력 실패 시 label/예약 보존과 덮어쓰기 거부.
- 누락 미끼 fetch 실패 시 C seed 미생성.
- 요청 body의 actor/c 조작 무시, 미인증·다른 역할의 Gateway context 거부.

배포 후에는 README의 체크리스트와 연구 설계 G1/G2를 실행하고,
정제된 runner 출력, DDB 상태/edge, S3 태그, 직접 API 거부 결과를 별도로 보존해야 한다.
저비용·낮은 오버헤드·탐지 성능에 대한 수치는 현재 없다.
