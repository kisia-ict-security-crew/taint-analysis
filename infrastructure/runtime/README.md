# 보관된 강제 중개 예비 프로토타입

> **최종 제안 아키텍처가 아닙니다.** 요청 경로 변경과 추가 지연·비용 때문에 본 논문의 연구축에서
> 제외했습니다. 코드는 과거 feasibility 실험의 재현 기록으로만 보존하며, 현재 연구 구현은
> [AWS 로그 기반 환경](../aws/README.md)을 사용합니다.

과거 실험의 연구 기준은 당시의 [RESEARCH_REDESIGN.md](../../RESEARCH_REDESIGN.md)였으나 현재 문서는
로그 기반 최종 설계로 교체되었다.
CloudTrail 로그가 없어도 요청 처리 중 C-/D-Taint를 확정하는 AWS Lambda broker다.
현재 S3 합성 미끼/중요 데이터와 STS worker 위임을 지원하며 운영 배포 전 연구 프로토타입이다.

## 구성과 구현

- `broker.py`: 인증된 credential 단위 단조 label, parent 상속, S3 read/put/copy, C∩D.
- `cloud-mine.schema.json`: 공통 지뢰 등록 명세 v1alpha1. 현재 kind는 `aws.s3-object`만 지원한다.
- `main.tf`: IAM 인증 API Gateway, Lambda, DynamoDB, S3, worker/broker 역할.
- `client.py`: SigV4 요청 전송. 데이터/자격증명을 CLI 출력에서 제외한다.
- `run_experiment.py`: B0/S1/S2, 직접 S3 우회 거부를 실제 AWS에서 검사한다.
- `run_cost_study.py`: 임시 지뢰 규모, 접촉, 직접/선택적 중개 지연과 요청량을 측정하고 정제된 결과를 만든다.
- `test_broker.py`: AWS 없는 단위 테스트. 배포 성공을 대체하지 않는다.

broker는 상태 저장 후 데이터/자격증명을 반환한다. worker는 API 호출만 허용된다.
지뢰별 C/D 발생 정책은 Lambda 코드가 아니라 DynamoDB의 `mine:<resource>` 등록 항목에서 읽는다.
현재 Terraform은 HoneyToken과 중요 데이터 지뢰 두 개를 동일 broker에 등록한다.
리소스 C는 발자국이며 그 객체를 읽는 타인의 침해를 자동 확정하지 않는다.
객체 D를 읽은 세션의 모든 후속 출력은 D가 된다. 정밀 byte-level taint가 아니다.
후속 개발 대상은 Pod/process, Secrets Manager, Lambda invocation, message, DB adapter다.

## 로컬 검증

`infrastructure/runtime` 디렉터리에서:

```powershell
python -m unittest discover -s . -p "test_*.py" -v
terraform init -backend=false
terraform validate
terraform fmt -check -recursive .
```

## AWS 실행

기존 `infrastructure/aws`와 별도의 Terraform root/state다. 기존 환경을 변경하거나 제거하지 않는다.
전용 계정에서 `terraform.tfvars.example`을 참고해 정확한 researcher IAM ARN을 `terraform.tfvars`에 설정한다.
researcher에는 worker AssumeRole을 허용하는 자체 IAM 권한도 필요하다.
secret key는 tfvars에 넣지 않고 AWS 프로파일을 사용한다.

Lambda의 예약 동시성은 사용하지 않는다. 새 계정은 전체 Lambda 동시성 한도가 10일 수 있고,
AWS는 그 10개를 모두 unreserved로 남겨야 하므로 function에 1개도 예약할 수 없다.
대신 broker는 작업 시작 전 DynamoDB의 전역 lease를 획득한다. lease를 얻지 못한 요청은 503으로
종료하므로 클라이언트가 새 요청 ID로 재시도해야 한다. 이 프로토타입은 전파 정확성을 위해
모든 broker 요청을 한 번에 하나만 처리한다. 처리량 확장은 안전한 shard/transaction 설계와 함께 별도 검증한다.

```powershell
cd infrastructure/runtime
terraform init
terraform plan -out=runtime.tfplan
terraform apply runtime.tfplan
python -m pip install -r requirements.txt
$runtimeEndpoint = terraform output -raw endpoint
$runtimeWorker = terraform output -raw worker_role
$runtimeBucket = terraform output -raw bucket
python run_experiment.py --endpoint $runtimeEndpoint --worker-role $runtimeWorker --bucket $runtimeBucket
```

저비용 가설의 실제 계측은 저장소 루트의 `LOW_COST_TAINT_DESIGN.md`를 먼저 읽고 다음처럼 실행한다.

```powershell
python run_cost_study.py `
  --endpoint $runtimeEndpoint `
  --worker-role $runtimeWorker `
  --bucket $runtimeBucket `
  --table (terraform output -raw state_table) `
  --output .\results\cost-study.json
```

이 실행은 최대 1,000개의 합성 임시 registry/object를 설치 후 정확한 key/version으로 정리한다. Broker가 만든 파생 객체와 상태는 실험 증거로 보존한다. 짧은 실행의 Cost Explorer 청구액 대신 API 수와 Lambda billed duration을 주 결과로 사용한다.

배포와 실행은 비용이 발생한다. 이 저장소 변경 작업에서는 실행하지 않았다.
`run_experiment.py`의 JSON은 실제 실행에서만 생성된다. stderr/credential을 포함한 전체 셸 기록 대신
정제된 stdout 결과를 보관한다. 실제 데이터·credential을 응답 로그나 API Gateway execution data trace에 기록하지 않는다.

API payload 예시:

```json
{"operation":"read","key":"seeds/honey.csv"}
{"operation":"delegate"}
{"operation":"read","key":"seeds/critical.csv"}
{"operation":"copy","key":"seeds/critical.csv","destination":"derived/unique-run/copy.csv"}
{"operation":"put","destination":"derived/unique-run/output.csv","data":"eA=="}
{"operation":"status"}
```

각 요청은 worker 자격증명으로 SigV4 서명해야 한다. parent는 서버가 정한다.
`delegate`가 반환하는 자식 자격증명을 다음 요청에 사용한다. CLI client는 이를 출력하지 않으므로
전체 체인 실행에는 `run_experiment.py` 또는 `client.invoke`를 이용한다.

## 검증해야 할 결과

1. 정상 write: c=false, d=false.
2. honey read 후 자식 위임과 critical copy: intersection=true.
3. 독립 세션의 critical read→transform→put: c=false, d=true.
4. S3 출력 태그: `taint-c`, `taint-d`; DynamoDB에는 상태와 edge가 존재.
5. worker의 직접 S3/STS/DynamoDB 접근: 거부. runner는 직접 S3만 자동 검사한다.
6. CloudTrail 수집/조회 없이 동일 동작. 기존 기업 감사 로그를 꺼야 한다는 뜻은 아니다.
7. Lambda 재기동 후 상태 보존, 인증 context의 accessKey/userArn 존재, timeout/retry 처리.

## 제한과 운영 전 과제

- Lambda concurrency=1은 정확성 조건이다. 단순 증설하면 안 된다. throttling 시 재시도 필요.
- managed service 전체를 투명하게 가로채지 않는다. 이 worker의 중개 작업만 보장한다.
- 64 KiB 이하 객체, `derived/`의 신규 key만 허용한다. copy는 GET+PUT이다.
- 실패한 output 예약은 남는다. 새 key로 다시 시도한다. 삭제/재사용/정확히 한 번 실행 미지원.
- 현재 resource identity는 bucket/key이고 overwrite를 막아 세대 혼동을 제한한다.
  관리자가 외부에서 overwrite하면 가정이 깨진다. 일반 versioned 객체 adapter는 후속 작업이다.
- DDB가 권위 상태다. S3 생성 태그는 가시화용이며 이후 C 접촉은 상태에만 기록된다.
- 별도 SNS 경보는 아직 없고 API 응답 및 DynamoDB edge에서 교차점을 확인한다.
- researcher/관리자나 broker 자체가 침해되면 우회할 수 있다. 관리 경계 강화는 별도 배포 검토 대상이다.
- state와 edge에는 TTL이 없어 보존 비용이 증가한다. 원인·근거 보존을 유지하는 압축을 평가해야 한다.
- `terraform destroy`는 상태 이력을 없앨 수 있다. 연구 결과를 내보내고 보존 정책을 결정한 뒤 수행한다.
