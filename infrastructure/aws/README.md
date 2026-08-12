# AWS 로그 수집 환경과 IaC 허니토큰

CloudTrail 관리 이벤트를 암호화된 S3 버킷과 CloudWatch Logs에 수집하고, 미끼 AWS Secrets Manager 비밀에 대한 조회 시도를 EventBridge가 탐지해 SNS로 알립니다.

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
```

## 파일 구조

```text
aws/
├─ versions.tf             # Terraform/AWS provider 버전
├─ variables.tf            # 입력 변수와 검증
├─ main.tf                 # KMS, S3, CloudTrail, CloudWatch
├─ honeytoken.tf           # 미끼 비밀, 탐지 규칙, SNS 경보
├─ outputs.tf              # 생성 리소스 식별자
├─ terraform.tfvars.example
├─ README.md               # 배포·시험·운영 안내
└─ STUDY.md                # 스터디 정리
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

- EventBridge 규칙은 `GetSecretValue`와 `DescribeSecret`을 모두 탐지합니다. 정상 운영 주체가 접근하지 않도록 미끼 ARN을 애플리케이션에 연결하지 않습니다.
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
