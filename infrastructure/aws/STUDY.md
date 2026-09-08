# AWS 로그 수집과 허니토큰 스터디 정리

> **역사적 배경 자료.** CloudTrail 설명과 기존 체크리스트입니다.
> 현재 실행 시점 전파 연구의 기준은 [RESEARCH_REDESIGN.md](../../RESEARCH_REDESIGN.md)입니다.

## 1. 목표

침해 주체(C-Taint)가 미끼 정보(D-Taint)에 접근하는 순간을 AWS 감사 로그에서 식별하고, 이후의 권한 전환과 리소스 접근을 같은 주체·세션·시간축으로 연결한다.

## 2. 왜 CloudTrail인가

CloudTrail 관리 이벤트는 AWS API 호출의 주체, 시간, 출발지, 요청 대상과 성공·실패 결과를 남긴다. 핵심 필드는 다음과 같다.

| 목적 | CloudTrail 필드 |
|---|---|
| 호출 시각 | `eventTime` |
| API/서비스 | `eventName`, `eventSource` |
| 행위 주체 | `userIdentity.type`, `userIdentity.arn`, `principalId` |
| 임시 세션 추적 | `userIdentity.sessionContext`, `accessKeyId` |
| 출발지 | `sourceIPAddress`, `userAgent` |
| 대상 | `requestParameters` |
| 결과 | `errorCode`, `errorMessage`, `responseElements` |
| 연계 분석 | `eventID`, `sharedEventID`, `requestID` |

멀티 리전 Trail과 글로벌 서비스 이벤트를 켜야 다른 리전의 활동 및 IAM·STS 같은 전역 이벤트 누락을 줄일 수 있다. 로그 파일 검증은 S3에 저장된 로그의 변경·삭제 여부를 검증하는 데 사용한다.

## 3. 수집 파이프라인

- **S3**: 원본 감사 로그 장기 보관. 버전 관리, 공개 차단, TLS 강제, KMS 암호화를 적용한다.
- **CloudWatch Logs**: Logs Insights로 빠르게 검색하고 분석한다. 보존 기간을 명시해 비용과 규정을 관리한다.
- **EventBridge**: CloudTrail API 이벤트 중 미끼 비밀 접근만 실시간에 가깝게 선별한다.
- **SNS**: 탐지 결과를 이메일 등 운영 채널로 보낸다.

CloudTrail 자체가 EventBridge에 API 이벤트를 전달하므로 경보를 위해 S3 파일을 다시 읽는 별도 Lambda는 필요하지 않다.

## 4. 허니토큰 설계

허니토큰은 정상 업무 흐름에서는 접근할 이유가 없는 미끼다. 이 실습은 `/honeytoken/prod/legacy-api-key`라는 Secrets Manager 경로를 만들고 `GetSecretValue`, `DescribeSecret` 호출을 탐지한다.

안전 원칙:

1. 실제로 동작하는 AWS 액세스 키를 허니토큰으로 만들지 않는다.
2. 미끼 값은 Terraform 코드·상태·Git에 넣지 않는다.
3. 애플리케이션과 배포 파이프라인에 미끼 ARN을 연결하지 않는다.
4. 정상 접근이 0건이라는 전제로 모든 접근을 조사한다.
5. 이름과 태그만으로도 미끼임을 운영자가 식별할 수 있게 한다.

## 5. C-Taint와 D-Taint 연결

1. `GetSecretValue` 이벤트에서 `userIdentity.arn`, 세션 발급자, 접근 키 ID, 출발지 IP를 추출한다.
2. 같은 `principalId` 또는 임시 세션을 기준으로 전후 시간대 이벤트를 조회한다.
3. `AssumeRole` 이벤트의 `responseElements.credentials.accessKeyId`와 이후 이벤트의 `userIdentity.accessKeyId`를 연결해 주체 전환을 추적한다.
4. 접근한 리소스 ARN·요청 파라미터를 D-Taint 전파 후보로 기록한다.
5. 동일 IP만으로 단정하지 않고 세션, 계정, User-Agent, 시간 근접성을 함께 사용한다.

예시 분석 흐름:

```text
의심 세션(C-Taint)
  → DescribeSecret
  → GetSecretValue(D-Taint 접촉)
  → AssumeRole(주체 전환)
  → S3/GetObject 또는 다른 중요 리소스 접근
```

## 6. 탐지 후 대응

1. SNS 경보의 시간, 주체 ARN, 출발지 IP, 비밀 ARN을 보존한다.
2. 해당 세션과 액세스 키를 비활성화하거나 권한을 차단한다.
3. 경보 전후 CloudTrail 이벤트를 수집해 타임라인을 만든다.
4. 같은 주체가 접근한 리소스와 수행한 권한 변경을 확인한다.
5. 미끼 외 실제 비밀 또는 데이터 접근 여부를 조사한다.
6. 정상 테스트였다면 테스트 주체와 시간을 기록하되 탐지 규칙을 무분별하게 예외 처리하지 않는다.

## 7. 한계와 개선점

- CloudTrail/EventBridge 전달에는 지연이 있을 수 있어 즉시 차단 장치로만 의존하면 안 된다.
- SNS 이메일은 초기 실습에 적합하지만 운영 환경에서는 보안 플랫폼, 티켓, 호출 시스템 연동이 필요하다.
- 단일 계정 구성이다. AWS Organizations 환경에서는 조직 Trail과 중앙 로그 아카이브 계정이 권장된다.
- 현재 미끼는 Secrets Manager 한 종류다. S3 미끼 객체, Parameter Store 경로, DynamoDB 레코드 등으로 확장할 수 있다.
- 로그 버킷에 Object Lock을 쓰려면 버킷 생성 시점부터 별도 설계가 필요하다.

## 8. 검증 체크리스트

- [ ] `terraform fmt -check`와 `terraform validate` 통과
- [ ] SNS 이메일 구독 확인 완료
- [ ] CloudTrail logging 상태 확인
- [ ] S3에 `AWSLogs/<account-id>/CloudTrail/` 객체 생성 확인
- [ ] 시험 접근 후 SNS 경보 수신
- [ ] Logs Insights에서 동일 이벤트 조회
- [ ] `userIdentity`와 `requestParameters.secretId`로 주체·대상 연결 확인
- [ ] 실습 종료 후 비용 리소스 정리 또는 보존 정책 확인
