# AWS 연구 환경 실행 절차

> **Legacy runbook.** 아래 API 실험은 감사 로그 기준선입니다. 새 온라인 실행 절차는
> [runtime/README.md](../runtime/README.md)를 따릅니다. 아래 R3/R4 프로브는 새 runtime 범위가 아닙니다.

이 문서는 Terraform 적용 이후 사람이 수행해야 하는 프로브와 로그 확인 절차다. 모든 객체와 비밀 값은 합성 데이터만 사용한다.

## 1. 배포 전 확인

```powershell
aws sts get-caller-identity
terraform fmt -check
terraform validate
terraform plan -out=tfplan
```

계정 ID가 전용 연구 계정인지 확인한 뒤에만 `terraform apply tfplan`을 실행한다. Terraform apply가 만든 관리 이벤트는 연구 공격 이벤트가 아니므로 apply 종료 시각을 기록하고 분석 구간에서 분리한다.

## 2. 콘솔에서 필요한 작업

1. SNS 구독 확인 메일의 **Confirm subscription**을 누른다.
2. CloudTrail 콘솔에서 trail의 Logging 상태와 S3 data event selector를 확인한다.
3. S3 로그 버킷의 `AWSLogs/<account-id>/CloudTrail/`에 로그가 도착하는지 확인한다.
4. CloudWatch Logs에서 `/aws/cloudtrail/<trail-name>` 로그 그룹을 확인한다.
5. Athena에서 Terraform이 만든 workgroup을 선택하고 `00_create_cloudtrail_raw_table` named query를 실행한다.
6. 프로브 날짜의 Athena partition을 추가한다. 경로 형식은 `.../CloudTrail/<region>/<year>/<month>/<day>/`이다.

SNS 확인과 Athena named query 실행을 제외한 인프라는 Terraform이 관리한다. 콘솔에서 IAM 정책이나 CloudTrail selector를 직접 수정하지 않는다.

## 3. Secret 씨앗 값 초기화

Terraform 상태에 값이 남지 않도록 Terraform 외부에서 한 번 넣는다.

```powershell
$secretArn = terraform output -raw honeytoken_secret_arn
aws secretsmanager put-secret-value --secret-id $secretArn --secret-string 'DECOY_ONLY_NOT_A_REAL_CREDENTIAL'
```

## 4. 최소 로그 프로브

먼저 Terraform outputs와 시작 시각을 정답지에 기록한다.

```powershell
terraform output -json
```

수동 명령 대신 `scripts/`의 재현 가능한 실행기를 사용하는 것이 기본 절차다. 각 실행기는 `runs/<run-id>/manifest.json`에 정답을 기록하고, 자격증명 환경과 임시 파일을 `finally`에서 복원·삭제한다.

정상 배경 작업을 먼저 실행한다.

```powershell
.\scripts\invoke-background.ps1 -Iterations 5 -IntervalSeconds 5
```

출력된 manifest 경로를 검증한다.

```powershell
.\scripts\verify-run.ps1 -ManifestPath ".\runs\background-...\manifest.json"
```

`verification.json`이 PASS이고 Data/Secret 씨앗 금지 이벤트가 0건일 때만 S1-a를 실행한다.

```powershell
.\scripts\invoke-s1a.ps1
.\scripts\verify-run.ps1 -ManifestPath ".\runs\s1a-...\manifest.json"
```

sourceIdentity 절제 실험은 최초 AssumeRole에 고정 값을 전달하는 별도 run으로 실행한다.

```powershell
.\scripts\invoke-s1a.ps1 -SourceIdentity "research-runner"
```

CloudTrail 전달이 늦으면 verifier가 기본 15분 동안 재조회한다. 원본 이벤트가 완전하지 않으면 임의로 채우지 않고 FAIL 결과를 보존한다.

현재 연구자 자격증명으로 ActorA를 assume한다. 기본 실험과 sourceIdentity 강화 실험을 구분한다. sourceIdentity를 사용하는 실험에서는 최초 AssumeRole에만 고정 값을 설정하고 체인 중간에서 바꾸지 않는다.

ActorA 자격증명으로 다음을 실행한다.

1. Data 씨앗 `GetObject` 성공 — R1-success 후보
2. Secret 씨앗 `GetSecretValue` 성공 — R1-success 후보
3. PivotB `AssumeRole`

PivotB 자격증명으로 PivotC를 `AssumeRole`하고, PivotC 자격증명으로 다음을 실행한다.

1. 중요 객체 `GetObject`
2. 중요 객체를 staging 버킷으로 `CopyObject`
3. staging 객체를 egress 버킷으로 `CopyObject`
4. 임시 객체 `PutObject`와 `DeleteObject`
5. 전용 persistence 사용자에 `CreateAccessKey`
6. 생성된 키로 중요 객체 `GetObject`
7. 즉시 `DeleteAccessKey`

생성된 access key secret은 화면·셸 기록·Git·Terraform state에 저장하지 않는다. 프로세스 메모리에서만 사용하고 `finally` 처리로 삭제한다. 자동 삭제를 보장하는 시나리오 실행기를 작성하기 전에는 R3 프로브를 생략하는 것이 안전하다.

## 5. R4 프로브

ActorA 자격증명으로 GrantTarget에 실험 버킷의 중요 객체 하나만 허용하는 인라인 정책을 `PutRolePolicy`로 추가한다. GrantTarget을 assume해 객체 읽기가 성공하는지 확인한 뒤 같은 정책 이름으로 `DeleteRolePolicy`를 호출한다.

이 실험의 scope는 단일 계정, permissions boundary 없음, SCP 영향 없음, 명시적 Deny 없음으로 제한한다. 이 조건 밖에서는 정책 부착이 실효 권한 부여를 뜻하지 않을 수 있다.

## 6. 거부 이벤트와 S2

- 별도 무권한 세션으로 Data/Secret 씨앗 접근을 시도해 AccessDenied 로그를 만든다. 이 이벤트는 R1-attempt이며 주 분석의 R1-success와 섞지 않는다.
- S2는 미끼에 접근하지 않는 별도 세션으로 AssumeRole → 중요 객체 조회 → egress 복사를 실행한다. S2에서 C-Taint가 시작되면 규칙 또는 데이터 라벨이 잘못된 것이다.

## 7. 로그 도착과 완전성 확인

CloudTrail은 파일 내부를 API 호출 순서대로 제공하지 않는다. 파일 순서 대신 `eventTime`, `eventID`, `requestID`, `accessKeyId`를 사용한다.

실험 종료 직후 한 번만 조회하지 말고 다음 조건으로 수집 완료를 판단한다.

1. 기대 이벤트 목록을 정답지에 기록한다.
2. 5분 간격으로 CloudWatch Logs 또는 Athena를 조회한다.
3. 기대 이벤트가 모두 도착하고 두 번의 조회에서 신규 이벤트가 없으면 window를 닫는다.
4. 최대 대기시간을 넘으면 누락으로 기록하고 임의로 채우지 않는다.
5. `aws cloudtrail validate-logs`로 원본 digest와 로그 무결성을 확인한다.

반드시 확인할 이벤트는 `GetObject`, `GetSecretValue`, `AssumeRole` 2건, `CopyObject`, `PutObject`, `DeleteObject`, `PutRolePolicy`, `DeleteRolePolicy`다. R3를 실행했다면 `CreateAccessKey`, 생성 키의 사용 이벤트, `DeleteAccessKey`도 확인한다.

## 8. 실험 종료

1. 생성한 access key가 0개인지 확인한다.
2. GrantTarget의 실험 인라인 정책이 제거됐는지 확인한다.
3. CloudTrail 로그와 정답지를 보존한다.
4. 실험 버킷만 정리하고 로그 버킷은 보존한다.
5. 로그 버킷을 삭제해야 할 때는 별도 백업과 보존 정책 확인 후 명시적으로 `allow_log_bucket_destroy=true`를 사용한다.
