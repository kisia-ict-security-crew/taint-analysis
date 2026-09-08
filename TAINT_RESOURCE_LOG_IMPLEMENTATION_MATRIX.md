# AWS 리소스·로그·상황별 C-/D-Taint 구현 부록

상태: 구현 기준 문서  
목적: 핵심 의미론을 반복하지 않고, AWS에서 어떤 로그를 보고 어떤 근거로 Taint를 생성·전파·중단할지
리소스별 구현 세부사항을 제공한다. C, D, typed intersection의 의미와 우선순위는
[핵심 설계](RESEARCH_REDESIGN.md)가 항상 우선한다.

## 1. 이 문서를 읽는 방법

각 리소스에서는 항상 다음 순서로 판단한다.

```text
1. 성공한 이벤트인가?
2. 행위 주체를 세션 단위로 식별할 수 있는가?
3. HoneyToken 또는 중요 자산 registry와 정확히 일치하는가?
4. source→destination 관계가 로그에 직접 존재하는가?
5. 없으면 추정할 것인가, 관측만 남길 것인가, 중단할 것인가?
6. C와 D가 처음 만났는가?
```

판정 결과는 다음 네 등급 중 하나여야 한다.

| 등급 | 뜻 | 논문에서의 사용 |
|---|---|---|
| `E1 EXACT` | 직접 식별자 또는 명시적 source→destination 관계가 있음 | 정확 전파·주요 교차 결과 |
| `E2 INFERRED` | 같은 실행 단위·시간창 등으로 강하게 추론함 | 후보·과도 전파율 측정 |
| `E3 OBSERVED` | 접근·변경·실패 사실만 확인됨 | 보조 경보·조사 단서 |
| `U UNSUPPORTED` | 현재 로그로 관계를 확인할 수 없음 | coverage 공백으로 공개 |

여기서 “모든 리소스”는 AWS의 모든 현재·미래 서비스를 지원한다는 뜻이 아니다. 침해 계보에 필요한
리소스 유형을 망라하고, 각 유형을 E1/E2/E3/U 중 하나로 빠짐없이 분류한다는 뜻이다. 새 서비스는
마지막의 확장 계약을 통과해야 지원 목록에 추가한다.

## 2. 공통 상태 모델

### 2.1 저장 대상

```text
Entity
  entity_id        # 세션 fingerprint, resource ARN+version, invocation/message ID 등
  entity_type
  first_seen
  last_seen
  c_sources[]      # C seed ID 집합
  d_classified[]   # 보호 대상으로 지정된 논리 자산의 D seed ID 집합
  d_lineage[]      # 데이터 version에만 적용하는 D 계보 seed ID 집합

Edge
  edge_id          # provider + account + region + eventID
  event_time
  ingest_time
  edge_type
  source_entity
  target_entity
  evidence_level   # E1/E2/E3/U
  evidence_ref     # 원본 로그 S3 URI 또는 안전한 내부 참조
  rule_version
  success

Intersection
  c_seed_id
  d_seed_id
  first_edge_id
  intersection_type
  evidence_level
```

`D-CLASSIFIED`는 중요 경로·secret·table 같은 논리 자산의 중요도를, `D-LINEAGE`는 특정 데이터
version에서 직접 이어진 내용 계보를 뜻한다. WRITE/DELETE 교차는 D-CLASSIFIED를, READ/COPY/DERIVE
교차는 정확한 D-LINEAGE를 우선 사용한다.

원본 access key, secret value, session token, 객체 내용, 메시지 payload 및 SQL 전문은 상태 저장소에
넣지 않는다. access key는 HMAC 또는 SHA-256 기반 fingerprint로 변환하고, 원본 로그 위치만 참조한다.

### 2.2 단조 전파

```text
C_new(target) = C_old(target) union incoming_C_sources
D_new(target) = D_old(target) union incoming_D_sources
```

기존 원인은 삭제하지 않는다. 엔터티가 종료되거나 자격증명이 만료되더라도 이력은 남는다. 오판 정정은
기존 edge를 지우는 대신 `SUPERSEDED_BY` 레코드와 정정 사유를 추가한다.

### 2.3 이벤트 처리 순서

CloudTrail 로그는 호출 순서대로 도착한다고 가정하지 않는다. `eventTime`으로 정렬하되 지연 도착을 위해
watermark를 두고, 새 parent 또는 seed edge가 들어오면 영향을 받는 후속 edge를 재평가한다. `eventID`는
중복 제거 키로 사용한다. AWS 문서도 CloudTrail 이벤트가 정렬된 stack trace가 아니라고 명시하므로,
단순 1회 순차 처리로 확정하면 안 된다.

## 3. 공통 로그 수집 계층

| 로그 | 반드시 수집할 내용 | Taint에서의 역할 | 주의점 |
|---|---|---|---|
| CloudTrail 관리 이벤트 | IAM, STS, 리소스 구성·권한·삭제 | C 제어 계보, 로그 훼손 감시 | 데이터 읽기 자체는 보이지 않는 서비스가 많음 |
| CloudTrail 데이터 이벤트 | 선택한 S3, Lambda, DynamoDB, SNS 등 | 실제 data-plane 접촉 | 기본 비활성·고용량·추가 비용 |
| 서비스 감사 로그 | EKS audit, RDS DAS, OpenSearch audit 등 | CloudTrail 내부 공백 보완 | 서비스별 비용·민감정보 검토 필요 |
| 애플리케이션 구조화 로그 | request/invocation/message/trace ID | 내부 변환 관계 보완 | payload 자체는 기록하지 않음 |
| 네트워크 로그 | VPC Flow, Route 53 Resolver, ALB/WAF/API access | 목적지·DNS·HTTP 접촉 보조 | payload D 계보는 증명하지 못함 |
| AWS Config·CloudTrail | Trail, selector, bucket, KMS, IAM 변경 | 증거 훼손 시도 | Taint 전파가 아니라 무결성 경보 |

CloudTrail 데이터 이벤트는 기본적으로 기록되지 않고 추가 비용이 발생한다. Advanced event selector는
`eventName`, `readOnly`, `eventSource`, `resources.ARN`, `resources.type`, `userIdentity.arn` 등을 기준으로
범위를 제한할 수 있다. wildcard 대신 `StartsWith` 등의 연산자를 사용한다.

공식 근거:

- [CloudTrail 데이터 이벤트와 advanced selector](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html)
- [CloudTrail 이벤트 필드](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html)
- [CloudTrail 지원 데이터 이벤트 리소스](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-events.html#data-events)

## 4. Identity·자격증명·권한 리소스

### 4.1 IAM User와 장기 access key

| 항목 | 구현 규칙 |
|---|---|
| 로그 | CloudTrail 관리 이벤트: `CreateAccessKey`, `UpdateAccessKey`, `DeleteAccessKey`, user·policy 변경 |
| C 생성 | 실제로 사용된 decoy access key가 registry와 일치하면 그 credential instance에 C seed |
| C 전파 | C 세션이 새 access key를 만들고 응답의 key ID를 확인할 수 있으면 새 credential에 E1 `C-CREDENTIAL-CREATE` |
| D 전파 | IAM 이벤트 자체에는 없음 |
| 교차 | C credential이 D 자산에 접근하는 실제 data-plane 이벤트에서 판정 |
| 중단 | key ID가 누락되거나 실제 사용 세션과 연결되지 않으면 E3 변경만 기록 |
| 금지 | IAM user 전체를 영구 C로 만들어 모든 정상 key를 오염시키지 않음 |

### 4.2 STS AssumeRole·federation

| 항목 | 구현 규칙 |
|---|---|
| 로그 | CloudTrail 관리 이벤트의 `userIdentity`, `requestParameters`, `responseElements`, `sourceIdentity` |
| source | 호출한 credential/session fingerprint |
| destination | 응답에서 확인한 assumed-role session ARN과 임시 access key fingerprint |
| C 전파 | source가 C이고 호출 성공·destination 식별 가능이면 E1 `C-ASSUME` |
| D 전파 | 기본적으로 하지 않음. 세션이 D에 접근했다는 사실과 권한 위임은 다른 관계 |
| 교차 | 자식 C 세션이 D를 읽을 때 발생 |
| 중단 | 실패 호출, 응답 식별자 누락, 독립 federation 로그인은 E3 또는 U |

`SourceIdentity`는 보조 식별자이지 유일한 신뢰 근거가 아니다. 같은 역할명이나 source IP만으로 parent를
추정하지 않는다.

### 4.3 IAM Role·policy·PassRole

| 상황 | 판정 |
|---|---|
| C 세션이 role policy를 변경 | role에 `C-CONTROLLED` E1 footprint; 즉시 모든 role session에 C를 전파하지 않음 |
| C 세션이 `PassRole`을 포함한 서비스 생성 API 실행 | 생성된 workload와 전달 role의 control edge 기록 |
| 변경된 role로 새 session 발급 | 실제 발급/실행 식별자가 연결될 때 C 후보를 E1 또는 E2로 승격 |
| 정상 관리자가 같은 role 사용 | 독립 session이면 자동 C 금지 |
| policy 변경 실패 | E3 시도만 기록 |

권한 제어 Taint와 실행 세션 C-Taint를 구분한다. `C-CONTROLLED(role)`은 “공격자가 정책을 바꿨다”는
사실이고, 그 role의 모든 과거·현재 작업이 공격자 소유라는 뜻이 아니다.

### 4.4 IAM Identity Center·콘솔·root

- CloudTrail의 `userIdentity.type`, issuer, principal/session 정보를 세션 엔터티로 정규화한다.
- 콘솔 세션과 API credential을 동일 사용자 이름만으로 합치지 않는다.
- root 사용은 별도 고위험 E3 경보이며 HoneyToken 접촉 또는 명시적 parent edge 없이는 C seed가 아니다.
- SSO 세션 식별 필드가 계정·리전 로그 사이에서 끊기면 U로 남긴다.

## 5. Secret·암호화 리소스

### 5.1 Secrets Manager

| 상황 | C/D 판정 |
|---|---|
| 등록된 Honey secret의 성공한 `GetSecretValue` | 호출 세션에 E1 C seed |
| Honey secret `DescribeSecret` | E3 접촉; 값 취득이 아니므로 C-success와 분리 |
| 실패한 `GetSecretValue` | E3 attempt |
| 중요 secret의 성공한 `GetSecretValue` | 세션에 E1 D exposure |
| `PutSecretValue`/rotation | 새 secret version을 별도 엔터티로 기록; 입력 데이터 의존은 U |
| secret 삭제·resource policy 변경 | control/훼손 E3, C actor가 수행하면 C footprint |

CloudTrail read 이벤트의 `responseElements`가 null일 수 있으므로 “응답에 secret 값이 없다”는 것이 실패를
의미하지 않는다. `errorCode` 부재와 서비스별 성공 조건을 함께 판정한다.

### 5.2 Systems Manager Parameter Store

- decoy SecureString의 성공한 `GetParameter(s)`/`GetParametersByPath`는 C seed 후보다.
- 중요 parameter 취득은 D exposure다.
- 경로 단위 조회는 반환된 정확한 parameter 식별자를 확인할 수 없으면 E2 또는 E3다.
- `PutParameter`는 데이터 파생 관계가 보이지 않으므로 D를 E1로 전파하지 않는다.

### 5.3 KMS

| 이벤트 | 판정 |
|---|---|
| C 세션의 `Decrypt` | C footprint·복호화 행위 E3 |
| 중요 데이터용 key의 `Decrypt` | key 사용 사실 E3; 어떤 plaintext를 얻었는지 모르므로 D 전파 금지 |
| `GenerateDataKey` | key 생성·사용 edge만 기록, 이후 ciphertext lineage는 U |
| key policy·grant 변경 | C actor라면 `C-CONTROLLED(key)` |
| key disable/schedule deletion | 로그/데이터 가용성 훼손 경보 |

KMS key가 중요하다는 사실과 그 key로 암호화된 모든 데이터가 동일 D라는 가정은 하지 않는다.

## 6. 객체·파일·블록 저장소

### 6.1 Amazon S3

S3가 현재 연구의 우선 구현 대상이다. 데이터 이벤트는 연구 대상 bucket 또는 prefix로 제한한다.

| 이벤트/상황 | C 규칙 | D 규칙 | 등급 |
|---|---|---|---|
| Honey `GetObject`/`GetObjectVersion` 성공 | 세션에 C seed | Honey가 중요 데이터가 아니면 D 없음 | E1 |
| Honey `HeadObject` | E3 접촉만 | 없음 | E3 |
| Honey GET 실패 | C-success 없음 | 없음 | E3 |
| 중요 객체 GET 성공 | C 세션이면 접근 교차 | 세션에 D exposure | E1 |
| `CopyObject` | C 세션이면 목적 객체에 C footprint | source version이 D면 destination version에 D | E1 |
| `GetObject` 후 `PutObject` | C 세션의 출력 footprint | 같은 세션·제한 시간창이면 D-derived 후보 | E2 |
| 일반 `PutObject`만 존재 | C actor이면 C footprint | 입력 관계가 없으므로 D 전파 금지 | E1 C / U D |
| `DeleteObject`/version 삭제 | C actor면 훼손 footprint | 과거 D 이력은 유지, resource state는 deleted | E3 |
| 객체 tag 변경·삭제 | projection 훼손 경보 | 권위 Taint 상태는 변경하지 않음 | E3 |
| `ListBucket` | Honey 위치 탐색 신호 | object read가 아니므로 D 없음 | E3 |
| pre-signed URL 사용 | 로그 identity가 서명자만 나타내면 실제 소비자 연결 불가 | 객체 접근은 기록하되 actor lineage는 E2/U | E2/U |
| cross-region replication | 원본·복제 version 연결 필드가 확인될 때만 D | service principal만으로 actor C를 이어 붙이지 않음 | E1/E2 |

객체 ID는 `s3://bucket/key?versionId=...`를 기본으로 한다. version ID를 얻을 수 없는 이벤트는
`bucket/key + event generation`으로 임시 식별하고 정밀도 저하를 표시한다.

Multipart upload는 `uploadId` 단위 상태를 둔다. 각 `UploadPartCopy`의 source를 모두 확인한 경우에만
완료 객체를 E1 D로 판정한다. 일반 `UploadPart`가 섞이거나 part 로그가 누락되면 E2 또는 U다.

### 6.2 EBS snapshot

- snapshot 생성·복사·공유·삭제는 CloudTrail 관리 이벤트로 control provenance를 기록한다.
- EBS direct API의 block data event를 수집할 경우 snapshot→block 접근을 관측할 수 있다.
- snapshot 전체를 D seed로 지정한 뒤 명시적 `CopySnapshot`은 목적 snapshot D 후보가 된다.
- EC2 파일시스템 내부에서 어떤 파일이 읽혔는지는 EBS/CloudTrail만으로 알 수 없어 U다.

### 6.3 EFS·FSx

- CloudTrail control-plane 이벤트는 filesystem·access point·mount target 변경만 보여준다.
- 파일 open/read/write 계보는 기본 CloudTrail로 지원하지 않는다.
- FSx 엔진별 audit log가 파일 경로·주체·성공 결과를 제공할 때만 D exposure를 만들고, 아니면 U다.
- 정확한 파일 lineage가 연구에 필요할 때에만 host audit/eBPF/서비스 audit를 선택 계측한다.

## 7. 데이터베이스·검색 리소스

### 7.1 DynamoDB

| 상황 | 구현 |
|---|---|
| 중요 table `GetItem`/`Query`/`Scan` | table 또는 안전하게 추출한 key digest에 D exposure |
| Honey item read | 정확한 key가 registry와 일치할 때 C seed |
| `PutItem`/`UpdateItem` | 같은 request에 source가 없으므로 D E1 전파 금지 |
| `Transact*`/`Batch*` | 개별 항목을 분해하되 누락·절단 시 table-level E2 |
| DynamoDB Streams | source item version→stream record는 E1, 소비 결과는 소비자 correlation 필요 |

request parameter에 실제 데이터가 포함될 수 있으므로 원문을 상태 DB에 복제하지 않는다. table 전체가
중요한 경우에도 가능하면 partition/sort key의 HMAC digest로 엔터티를 구분한다.

### 7.2 RDS·Aurora

CloudTrail control-plane 로그만으로 SQL `SELECT`, row read, 변환을 볼 수 없다.

| 로그 | 가능한 판정 |
|---|---|
| CloudTrail RDS 관리 이벤트 | instance/cluster/snapshot 생성·변경·공유·삭제 |
| RDS Data API data event | 호출 주체·DB cluster·API 요청, 제공 필드 범위에서만 E1/E2 |
| Database Activity Streams | DB session, SQL command, accessed object 등 DB 활동 |
| engine audit log | DB user·query·object 접근; 엔진별 품질 차이 |

중요 table read는 DB session에 D exposure로 기록할 수 있지만 row→새 row 또는 DB→S3의 정확한 데이터
의존은 query parser·transaction ID·application trace가 없으면 E2/U다. Database Activity Streams는
SQL 전문과 bind 정보 등 민감 내용을 포함할 수 있으므로 원문 접근통제와 최소 수집이 필수다.

- [RDS Database Activity Streams](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/DBActivityStreams.html)
- [Database Activity Streams의 민감정보 주의](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/DBActivityStreams.Monitoring.html)

### 7.3 OpenSearch·ElastiCache·MemoryDB

- CloudTrail은 domain/cluster 관리 작업의 control provenance로 사용한다.
- OpenSearch audit logs에서 authenticated user, index, action, response를 확인할 때 index/document D exposure를 판정한다.
- query result가 이후 어디에 사용됐는지는 application trace가 없으면 U다.
- cache get/set의 key·value lineage는 기본 관리 로그로 보이지 않으므로 U다.

## 8. 함수·컨테이너·가상머신

### 8.1 Lambda

Lambda `Invoke`는 `AWS::Lambda::Function` 데이터 이벤트로 선택 수집할 수 있다.

| 경계 | 판정 |
|---|---|
| C 세션→Invoke | caller에서 특정 function invocation으로 C control edge E1 |
| D resource reference가 명시된 invoke | reference 전달은 E1, payload가 실제 D인지 여부는 E2 |
| invocation 내부 S3/DB 접근 | execution role 세션은 관측 가능하지만 invocation ID와 직접 연결되지 않으면 E2/U |
| function output | destination API와 invocation correlation이 없으면 D lineage U |
| async invoke·retry | request/event ID로 별도 attempt를 유지하고 중복 실행을 합치지 않음 |

정확한 invocation 내부 계보가 필요한 함수에만 `aws_request_id`, trace ID, 입력·출력 resource ID를 담은
구조화 로그를 추가한다. payload 원문이나 C/D 값을 클라이언트 입력에서 신뢰하지 않는다.

- [Lambda Invoke 데이터 이벤트](https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html)

### 8.2 ECS·Fargate

- `RunTask`, `StartTask`, task definition·service 변경은 CloudTrail control edge다.
- C actor가 시작한 task ARN에는 C-controlled 실행 후보를 붙인다.
- task role credential의 이후 API와 정확히 연결되는 식별자가 있을 때만 C를 승격한다.
- 컨테이너 내부 파일·메모리·socket lineage는 CloudTrail로 보이지 않는다.
- Fargate는 임의 host kernel 계측을 가정하지 않고 FireLens 구조화 로그·OpenTelemetry를 선택 사용한다.
- ECS Exec 사용 시 CloudTrail과 Session Manager 로그를 보조 증거로 수집한다.

### 8.3 EKS

| 로그 | 보이는 것 | 보이지 않는 것 |
|---|---|---|
| CloudTrail | EKS·AWS API, IRSA 사용 시 service account 관련 identity | 컨테이너 내부 데이터 흐름 |
| EKS `audit` log | Kubernetes user, verb, object, response status | 파일 byte·프로세스 메모리 |
| application/OTel log | request·trace·resource ID | 계측하지 않은 라이브러리 내부 흐름 |
| node audit/eBPF | process/file/socket edge | Fargate·managed boundary 내부 |

C actor가 Pod/Secret/RoleBinding을 생성·변경한 사실은 control footprint다. Kubernetes Secret GET 성공은
등록 seed와 일치하면 C 또는 D exposure가 될 수 있다. 그러나 같은 service account의 모든 Pod를 자동
C로 만들지 않고 Pod UID·container ID·session 식별이 확인될 때만 전파한다.

EKS control-plane audit log는 기본적으로 CloudWatch Logs에 전송되지 않으며 선택적으로 활성화해야 하고,
전달은 best effort다.

- [EKS control-plane audit logging](https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html)

### 8.4 EC2

- `RunInstances`는 caller→instance의 control edge다.
- instance profile을 가진 instance의 AWS API 호출은 role session으로 관측하되, launcher가 C였다는 이유만으로
  모든 instance API를 E1 C로 만들지 않는다.
- SSM Run Command/Session Manager는 command ID·instance ID·actor를 연결하고, 명령 실행 로그를 별도
  S3/CloudWatch에 보존할 때 실행 provenance를 보강한다.
- OS 파일·프로세스·메모리·socket D lineage는 CloudTrail로 알 수 없어 U다.
- 필요한 실험에서만 Linux audit/eBPF/OTel을 도입하고 instance ID, process start time, inode generation을 사용한다.

### 8.5 Step Functions·Glue·EMR·Athena

- 실행 시작 actor와 execution/job/query ID는 control edge로 기록한다.
- input/output 위치가 S3 URI로 명시되면 resource reference edge는 E1이다.
- 실제 결과가 어떤 입력 byte에서 파생됐는지는 job/query 정의와 execution log가 없으면 E2다.
- Athena query result 위치와 query execution ID를 연결하고, 입력 table/location은 query·catalog 분석으로
  E2 lineage를 만들 수 있다.
- 실행 입력·query text에 민감정보가 있을 수 있으므로 상태 저장소에는 digest와 resource ID만 보존한다.

## 9. 메시지·이벤트·스트림

메시지 시스템은 “topic/queue에 접근했다”와 “특정 메시지의 데이터를 전달했다”를 분리해야 한다.

### 9.1 SQS

| 상황 | 판정 |
|---|---|
| C 세션의 `SendMessage` | queue 접촉 C footprint; message ID가 확인되면 message C 후보 |
| D-exposed 세션의 send | payload 의존이 보이지 않으므로 message D는 E2 |
| `ReceiveMessage` | 응답에 message ID가 안전하게 연결되지 않으면 특정 message→consumer는 E2/U |
| batch send/receive | message별 ID로 분해할 수 없으면 batch entity E2 |
| retry/redelivery | 같은 message ID의 delivery edge를 추가하고 새 데이터 생성으로 보지 않음 |
| DLQ 이동 | 원 message ID와 연결되면 label 유지, 아니면 queue-level E2 |

정확한 message lineage가 필요하면 producer가 서명된 내부 provenance reference를 message attribute에 넣고,
consumer가 message ID·request/trace ID를 구조화 로그로 남긴다. 외부 입력의 임의 `taint=true`는 신뢰하지 않는다.

### 9.2 SNS

- `Publish`와 `PublishBatch`는 CloudTrail 데이터 이벤트로 선택 수집할 수 있다.
- publisher→topic 접촉은 E1이지만 subscriber별 실제 전달 성공과 payload D 계보는 별도 delivery log가 필요하다.
- message ID를 얻으면 message entity를 만들고, D-exposed publisher의 전송은 기본 E2다.
- SMS/외부 endpoint처럼 상대 로그가 없는 경계에서는 전파를 중단하고 egress candidate로 기록한다.

- [SNS Publish 데이터 이벤트](https://docs.aws.amazon.com/sns/latest/dg/logging-using-cloudtrail.html)

### 9.3 EventBridge·Kinesis·MSK

- EventBridge `PutEvents`, Kinesis `PutRecord(s)` 등 지원 data event를 선택 수집한다.
- stream/topic/partition/record ID가 확인되면 producer→record edge를 만든다.
- batch에서 개별 record ID가 누락되거나 consumer checkpoint만 보이면 E2다.
- payload D 여부는 application provenance가 없으면 E2/U다.
- MSK cluster 내부 record lineage는 CloudTrail management log로 보이지 않으므로 cluster/client audit 또는
  OpenTelemetry correlation이 필요하다.

## 10. API·웹·네트워크·외부 반출

### 10.1 API Gateway·ALB·WAF·CloudFront

| 로그 | 사용 |
|---|---|
| API Gateway access/execution log | request ID, route, status, authenticated principal |
| ALB access log | target, URL, response, trace ID |
| WAF log | rule match, action, request metadata |
| CloudFront standard/realtime log | edge request, URI, status, request ID |

고유 Honey URL·path·header token의 성공 요청은 C seed가 될 수 있다. 단, source IP만 얻은 경우에는 네트워크
주체 C이며 AWS credential C와 자동 결합하지 않는다. backend 호출과 동일 trace/request ID가 연결될 때만
서비스 실행 문맥으로 C를 전파한다.

HTTP response에 D가 포함됐는지는 access log만으로 증명할 수 없다. 애플리케이션이 응답에 사용한 내부
resource ID와 trace ID를 구조화 로그로 남길 때 E1/E2 lineage를 만들 수 있다.

### 10.2 Route 53 Resolver query log

- 고유 honey domain 조회는 ENI/workload의 C 접촉 후보다.
- NAT·공유 resolver 뒤 client가 구분되지 않으면 E2다.
- DNS 조회만으로 URL fetch나 credential 사용 성공을 주장하지 않는다.
- 정상 보안 scanner·DNS crawler의 접촉을 별도 seed type으로 표시해 오탐 분석에 포함한다.

### 10.3 VPC Flow Logs

- C workload ENI에서 외부 목적지로 연결된 사실은 egress E3다.
- byte 수와 ACCEPT/REJECT는 네트워크 전송 메타데이터이지 D payload 증거가 아니다.
- 따라서 `C source + 많은 bytes`만으로 C∩D 유출을 만들지 않는다.
- D가 외부로 나갔다는 판정에는 proxy/DLP/application trace 등 별도 payload-aware 근거가 필요하다.
- Flow Logs가 캡처하지 않는 트래픽과 필드 제약을 coverage에 반영한다.

- [VPC Flow Logs 제한](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs-limitations.html)

### 10.4 NAT Gateway·VPC endpoint·PrivateLink

- NAT/endpoint flow 및 CloudTrail network activity event는 사용 가능한 범위에서 경로·거부 사실을 제공한다.
- 여러 workload가 공유 NAT를 사용할 경우 public IP만으로 actor를 합치지 않는다.
- `VpceAccessDenied`는 정책 거부 신호 E3이며 데이터 접근 성공이 아니다.
- interface endpoint ID와 workload ENI를 매핑할 수 있어도 payload D는 추론하지 않는다.

## 11. 코드·이미지·배포 공급망

### 11.1 ECR

- image manifest와 layer digest를 엔터티 ID로 사용한다.
- C actor의 image push·policy 변경은 image/repository C footprint다.
- 중요 코드 또는 secret이 포함된 것으로 등록된 image digest는 D seed가 될 수 있다.
- image pull과 실제 실행은 다른 edge다. ECS task ARN·EKS Pod UID·Lambda image digest 연결이 있을 때
  execution edge를 만든다.

### 11.2 CodeCommit·CodeBuild·CodePipeline·CodeArtifact

- commit SHA, artifact digest, build ID, pipeline execution ID를 사용한다.
- C actor의 source 변경 또는 build 시작은 control edge다.
- build input→artifact output은 build manifest와 digest가 있으면 E1, 단순 시간 상관이면 E2다.
- artifact 다운로드와 실행을 구분한다.
- build log의 secret 노출을 피하고 provenance에는 digest·resource reference만 저장한다.

## 12. 탐지·보안 서비스의 위치

GuardDuty, Security Hub, Inspector, Macie, Detective 결과는 독립 탐지 신호다.

- finding 자체를 자동 C seed로 사용하지 않는다.
- HoneyToken C∩D와 동일 principal/resource/time에 finding이 있으면 위험 점수를 올린다.
- Macie의 민감 데이터 분류는 D seed registry를 만드는 입력으로 사용할 수 있으나, classification job
  version과 범위를 기록한다.
- finding 종료·suppression은 Taint 원인을 삭제하지 않는다.

즉, 보안 서비스는 계보 전파 엔진의 근거를 보강하지만 그 자체가 데이터 lineage는 아니다.

## 13. 상황별 공통 판정표

| 상황 | 반드시 적용할 규칙 |
|---|---|
| API 성공 | 서비스별 성공 조건 확인 후 seed/edge 생성 |
| AccessDenied·오류 | C/D success 생성 금지, E3 attempt만 기록 |
| 응답 필드 null | read API는 정상일 수 있으므로 `errorCode`와 서비스 의미로 판정 |
| retry | 같은 eventID는 제거; 다른 eventID는 별도 attempt로 유지 |
| out-of-order/late event | watermark 이후 fixed-point 재전파 |
| 동일 역할의 여러 세션 | session/access-key fingerprint로 분리 |
| 장기 credential | key 자체와 각 사용 session/기간을 구분 |
| batch | item/message별 식별 가능할 때만 E1, 아니면 batch E2 |
| fan-out | 식별된 각 destination에 독립 edge |
| fan-in | 확인된 source 원인 집합을 union; 보이지 않은 input은 추가하지 않음 |
| read→transform→write | 동일 session만으로 E1 금지, E2 후보 |
| overwrite | 새 resource version 생성; 과거 label 유지 |
| delete | 상태를 deleted로 표시하되 계보 삭제 금지 |
| tag 삭제 | projection 훼손; 권위 상태 불변 |
| encryption | key 사용과 plaintext lineage 분리 |
| cross-account | `sharedEventID`, source/recipient account와 양쪽 로그로 결합; 한쪽만 있으면 E2 |
| cross-region | region을 entity/edge key에 포함 |
| service principal | `invokedBy`, source ARN/account 등 직접 필드가 있을 때만 caller 연결 |
| anonymous/pre-signed | signer·consumer를 구분할 수 없으면 E2/U |
| field truncation/omission | 해당 edge를 U로 낮추고 누락률 집계 |
| 로그 미수집 | negative 결과가 아니라 `NO_COVERAGE` |
| scanner의 Honey 접촉 | C seed type을 scanner/test/unknown으로 나눠 precision 평가 |
| 로그 설정 변경 | Taint가 아닌 evidence-integrity 경보 |
| 관리자에 의한 정정 | append-only superseding record, 원본 보존 |

## 14. 최초 교차점 판정 알고리즘

```text
for each normalized event ordered by eventTime with late-arrival replay:
    if duplicate(eventID): skip
    classify success and evidence level
    resolve exact actor/session/resource versions

    if successful_honey_contact:
        add C seed to actor session

    if exact_control_edge and source has C:
        union source.C into destination.C

    if exact_D_seed_read:
        record exposure(actor session, D object)

    if exact_data_copy and source has D:
        union source.D into destination.D

    if only temporal/session correlation exists:
        create E2 candidate; do not mutate E1 state

    if C actor performs READ/WRITE/DELETE/COPY on D data:
        conditionally write the first typed intersection for each (C seed, D seed)
```

E1 상태와 E2 후보 상태는 별도 필드 또는 별도 table로 유지한다. E2가 존재한다는 이유로 E1 전파의
입력을 만들지 않는다. 그렇지 않으면 한 번의 추정이 이후 전체 경로를 “정확”하게 오염시키는 문제가 생긴다.

## 15. 로그별 최소 정규화 필드

| 원본 | 필수 필드 |
|---|---|
| CloudTrail | eventID, eventTime, eventSource, eventName, awsRegion, recipientAccountId, userIdentity, requestParameters, responseElements, resources, errorCode, readOnly, sharedEventID |
| EKS audit | auditID, stageTimestamp, verb, user, sourceIPs, objectRef, request/response status, annotations |
| application/OTel | trace ID, span ID, request/invocation ID, authenticated workload ID, input/output resource reference, success |
| S3/access logs | request ID, time, operation, bucket/key/version, status, principal |
| DB audit/DAS | DB resource, DB session, transaction ID, user, command class, accessed object, success |
| network | account, region, VPC/subnet/ENI, src/dst, port/protocol, action, bytes, start/end |

필수 필드가 없으면 adapter가 임의 값을 생성하지 않고 `missing_fields[]`와 U/E2 판정을 출력한다.

## 16. IaC 구현 기준

### 현재 Terraform에서 유지할 것

- multi-region CloudTrail과 log file validation
- KMS 암호화 로그 버킷, versioning, public access block, TLS 강제
- CloudWatch Logs 전달
- Secrets Manager HoneyToken 경보
- 연구 S3 버킷의 data event
- Athena·Glue 분석 환경과 비용 budget

### 다음 Terraform 수정 순서

1. 기존 bucket 전체 basic event selector를 advanced event selector로 바꿀지 비용 실험용 변수로 분리한다.
2. `all`, `scoped`, `management-only` 세 수집 모드를 변수로 제공한다.
3. scoped 모드에는 HoneyToken과 중요 자산 ARN/prefix, 필요한 eventName만 포함한다.
4. 로그 selector 변경·Trail 중지·bucket/KMS policy 변경에 대한 EventBridge 경보를 추가한다.
5. 권위 상태 저장용 DynamoDB table을 추가하되 원문 로그와 secret은 저장하지 않는다.
6. S3 log-created event 또는 정해진 배치로 analyzer Lambda를 실행하고 idempotency key를 eventID로 둔다.
7. E1 state, E2 candidate, edge, first intersection을 분리한 key schema를 적용한다.
8. DLQ와 재처리 경로를 두고, 분석 실패를 정상적인 “교차 없음”으로 처리하지 않는다.
9. 실제 도입에서는 조직 trail과 별도 log archive account를 선택 옵션으로 제공한다.

Advanced selector의 실제 지원 필드와 resource type은 배포 시점의 AWS 문서 및 provider schema로 다시
검증한다. 현재 실험의 단일 account·bucket 구성을 조직 전체 운영 구성으로 그대로 일반화하지 않는다.

## 17. 리소스 adapter 추가 계약

새 AWS 서비스는 다음 열을 모두 채우기 전에는 “지원”이라고 표시하지 않는다.

```text
service/resource type
exact entity identifier and generation/version
available audit log and enablement method
success/failure rule
C seed rule
C propagation rule
D seed rule
D propagation rule
intersection rule
evidence level
batch/retry/out-of-order behavior
missing-field behavior
sensitive-field redaction
collection and retention cost
ground-truth test scenario
negative control scenario
```

하나라도 정의되지 않으면 지원 상태는 `PARTIAL` 또는 `UNSUPPORTED`다.

## 18. 구현 우선순위

| 단계 | 범위 | 이유 |
|---|---|---|
| P0 | STS + S3 + Secrets Manager | 현재 IaC와 로그가 있고 E1 교차를 검증 가능 |
| P1 | 상태 원인 집합, 증거 수준, object version, 최초 교차 | 논문 핵심 주장을 정확히 표현 |
| P2 | 선택 수집 비용 비교와 반복 자동화 | 최소비용 주장을 실제로 검증 |
| P3 | Lambda invocation correlation | 서버리스의 대표적인 관측 공백 검증 |
| P4 | SQS/SNS message correlation | 비동기 경계의 E1/E2 한계 검증 |
| P5 | EKS 또는 RDS 한 종류 | 선택 계측 비용과 coverage 증가 비교 |
| P6 | 다른 CSP adapter | AWS 의미론이 안정된 뒤 이식성 평가 |

한꺼번에 모든 서비스에 adapter를 만드는 것은 목표가 아니다. P0~P2에서 논문의 핵심 가설을 먼저
검증하고, 이후 서비스는 coverage 증가량 대비 로그·계측 비용이 큰 순서로 선택한다.

## 19. 구현 완료의 정의

어떤 리소스가 구현됐다고 말하려면 다음이 모두 충족되어야 한다.

- IaC로 필요한 로그를 켜고 수집 범위를 재현할 수 있음
- 성공, 실패, 독립 세션, retry, 누락 로그의 대조군이 있음
- 원본 로그를 사용하고 manifest 정답을 분석 입력으로 사용하지 않음
- E1/E2/E3/U와 중단 조건이 결과에 표시됨
- C/D 원인 seed와 최초 교차 edge를 재현할 수 있음
- 민감정보가 Git 산출물과 상태 DB에 들어가지 않음
- 이벤트 수, 지연, 저장량, 비용 및 coverage를 함께 보고함

이 조건을 통과하지 않은 서비스는 문서상 설계 또는 향후 작업이며, 논문 결과표에서 구현 완료로 표시하지
않는다.

## 20. 무결성 근거

CloudTrail log file validation은 전달 로그의 hash와 서명된 digest chain으로 전달 후 수정·삭제 여부를
검증할 수 있게 한다. 기능을 켜는 것만으로 검증이 수행되는 것은 아니므로 실험 종료 후 실제
`aws cloudtrail validate-logs` 결과를 보존해야 한다.

- [CloudTrail log file integrity validation](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html)
- [AWS CLI로 CloudTrail 로그 검증](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-cli.html)
- [AWS 로그 보관 계정 지침](https://docs.aws.amazon.com/prescriptive-guidance/latest/security-reference-architecture/log-archive.html)

최종적으로 이 연구가 제공하는 것은 “모든 byte의 완전한 추적”이 아니다. 기존 AWS 로그가 직접 증명하는
구간은 정확하게 연결하고, 추정과 관측 공백을 숨기지 않으면서, HoneyToken 접촉과 중요 데이터 접근의
최초 교차점을 최소한의 추가 수집 비용으로 찾는 체계다.
