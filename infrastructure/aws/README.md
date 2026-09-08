# AWS 로그 기반 Taint 연구 환경

이 디렉터리가 최종 연구 방향의 공식 AWS IaC와 분석 구현입니다. 기존 워크로드의 요청 경로를 변경하지
않고 CloudTrail 관리 이벤트와 선택된 S3 데이터 이벤트로 C-/D-Taint 계보를 재구성합니다.

리소스와 로그마다 적용할 C/D 규칙, 증거 수준, 중단 조건 및 추가 계측 기준은
[AWS 리소스·로그·상황별 구현 명세](../../TAINT_RESOURCE_LOG_IMPLEMENTATION_MATRIX.md)를 따릅니다.

CloudTrail 관리 이벤트와 연구 버킷의 S3 데이터 이벤트를 암호화된 S3 버킷과 CloudWatch Logs에 수집합니다. Secrets Manager 미끼와 S3 Data 씨앗 접근은 EventBridge가 선별하여 SNS로 알립니다. A→B→C 역할 체인, R4 권한 부여 대상, R3 자격증명 발급 대상, Athena 분석 기반도 함께 생성합니다.

> 이 구성은 실제 IAM 액세스 키나 유효한 자격 증명을 만들지 않습니다. 허니토큰 값은 Terraform 상태에 남기지 않기 위해 IaC에서 생성하지 않습니다.

## 구성

```text
AWS API activity
  └─ CloudTrail (multi-region, log validation)
       ├─ KMS 암호화 S3 (장기 보관, public access 차단)
       ├─ CloudWatch Logs (검색 및 분석)
       └─ EventBridge rule (GetSecretValue/DescribeSecret)
            └─ SNS email alert

Secrets Manager
  └─ /honeytoken/prod/legacy-api-key (빈 secret container)

Experiment plane
  ├─ critical / staging / egress-sim private buckets
  ├─ synthetic Data seed and synthetic critical object
  ├─ ActorA → PivotB → PivotC role chain
  ├─ GrantTarget role for R4
  └─ lab-only IAM user for R3

Analysis plane
  └─ Glue database + Athena workgroup + encrypted result bucket
```

## 파일 구조

```text
aws/
├─ versions.tf             # Terraform/AWS provider 버전
├─ variables.tf            # 입력 변수와 검증
├─ main.tf                 # KMS, S3, CloudTrail, CloudWatch
├─ storage.tf              # 실험 버킷, Data 씨앗, 중요 데이터
├─ iam_experiment.tf       # A→B→C, R3/R4 실험 신원
├─ analytics.tf            # Glue, Athena, 분석 결과 버킷
├─ budget.tf               # 월 비용 예산
├─ honeytoken.tf           # 미끼 비밀, 탐지 규칙, SNS 경보
├─ outputs.tf              # 생성 리소스 식별자
├─ terraform.tfvars.example
├─ README.md               # 배포·시험·운영 안내
├─ STUDY.md                # 스터디 정리
├─ RUNBOOK.md              # 배포 후 프로브와 로그 확인 절차
├─ DECISIONS.md            # 구현된 C-/D-Taint 의미론과 평가 경계
├─ THEORY_TODO.md          # 통계·범위 확장을 위한 후속 과제
├─ analysis/               # CEM adapter, taint engine, 테스트, 결과 집계
└─ scripts/                # B0/S1-a/S2 실행·검증·분석기
```

## 사전 준비

- Terraform 1.6 이상
- AWS CLI와 배포 권한이 있는 AWS 자격 증명
- 비용이 발생할 수 있는 항목: CloudTrail, S3, CloudWatch Logs, KMS, Secrets Manager, SNS

## 배포

```bash
cd infrastructure/aws
cp terraform.tfvars.example terraform.tfvars
# terraform.tfvars의 alert_email을 본인 주소로 변경
terraform init
terraform fmt -check
terraform validate
terraform plan -out=tfplan
terraform apply tfplan
```

`terraform apply`는 실제 AWS 자원을 생성하고 비용을 발생시킵니다. 적용 전에 반드시 전용 연구 계정인지 `aws sts get-caller-identity`로 확인하세요. 이 저장소에서 자동으로 apply하지는 않습니다.

배포 후 실험 절차는 [RUNBOOK.md](RUNBOOK.md)를 따릅니다.

C-/D-Taint 핵심 실험은 `scripts/invoke-background.ps1`, `scripts/invoke-s1a.ps1`, `scripts/invoke-s2.ps1` 순서로 실행하고 각 manifest를 `verify-run.ps1` 및 `analyze-run.ps1`에 전달합니다. 최종 판정 의미론과 한계는 [루트 설계 문서](../../RESEARCH_REDESIGN.md), 상세 명령은 [analysis/README.md](analysis/README.md)를 참조하세요.

배포 후 SNS가 보내는 구독 확인 메일에서 **Confirm subscription**을 눌러야 이메일 경보가 전달됩니다.

미끼 값이 꼭 필요하면 Terraform 밖에서 넣습니다. 값은 절대로 실제 자격 증명처럼 다른 시스템에서 유효하면 안 됩니다.

```bash
aws secretsmanager put-secret-value \
  --secret-id /honeytoken/prod/legacy-api-key \
  --secret-string 'DECOY_ONLY_NOT_A_REAL_CREDENTIAL'
```

## 탐지 시험

다음 명령은 의도적으로 경보를 발생시킵니다.

```bash
aws secretsmanager get-secret-value \
  --secret-id /honeytoken/prod/legacy-api-key
```

CloudTrail 전달과 EventBridge 매칭에는 몇 분이 걸릴 수 있습니다. SNS 메일에는 이벤트 원문이 포함되며 `userIdentity`, `sourceIPAddress`, `eventTime`, `eventName`, `requestParameters.secretId`를 우선 확인합니다.

CloudWatch Logs Insights 예시:

```sql
fields @timestamp, eventName, userIdentity.arn, sourceIPAddress, requestParameters.secretId
| filter eventSource = "secretsmanager.amazonaws.com"
| filter eventName in ["GetSecretValue", "DescribeSecret"]
| sort @timestamp desc
```

## 보안·운영 주의사항

- EventBridge 규칙은 `GetSecretValue`와 `DescribeSecret`을 모두 탐지하지만, R1-success 씨앗은 성공한 `GetSecretValue`만 사용합니다. `DescribeSecret`과 거부된 호출은 탐지 신호 또는 별도 민감도 분석으로 분리합니다.
- CloudTrail 로그 파일 검증을 켜고 S3 버킷의 버전 관리, 공개 차단, TLS 강제를 적용했습니다.
- KMS 키 정책은 계정 관리자와 CloudTrail, CloudWatch Logs, EventBridge의 필요한 암호화 작업만 허용합니다.
- `terraform.tfvars`, 상태 파일, plan 파일은 커밋하지 않습니다.
- 로그 보존이 기본값이므로 버킷에 객체가 있으면 삭제가 거부됩니다. 실습 정리 때만 `allow_log_bucket_destroy = true`를 사용합니다.
- 이메일 주소는 SNS 구독 리소스와 Terraform 상태에 기록될 수 있습니다. 공용 저장소에는 실제 주소가 든 tfvars를 올리지 않습니다.

## 정리

```bash
terraform destroy -var='allow_log_bucket_destroy=true'
```

S3 버킷이 비어 있지 않으면 삭제가 거부됩니다. 보존 정책에 따라 로그를 백업하거나 비운 후 다시 정리합니다.
