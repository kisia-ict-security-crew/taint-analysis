# 재현 가능한 실험 실행기

## 목적

- 정상 배경 활동과 공격 활동을 서로 다른 IAM 역할로 실행한다.
- 모든 실행에 고유 run ID와 역할 세션명을 사용한다.
- 실행한 단계와 기대 CloudTrail 이벤트를 manifest로 남긴다.
- CloudWatch Logs 원본과 manifest를 자동 대조한다.
- Secret 값, access key secret, STS session token은 기록하지 않는다.

## 파일

- `common.ps1`: Terraform output, AWS JSON 호출, 세션 교체·복원, manifest 공통 함수
- `invoke-background.ps1`: 미끼에 접근하지 않는 정상 Put/Get/Copy/Delete 작업
- `invoke-s1a.ps1`: Data/Secret 씨앗 → A→B→C → 중요 데이터 read/copy 시나리오
- `invoke-s2.ps1`: 씨앗 접촉 없이 A→B→C → 중요 데이터 read/copy를 수행하는 D-only 대조군
- `verify-run.ps1`: 기대 이벤트와 금지 이벤트를 CloudWatch Logs에서 자동 검증
- `analyze-run.ps1`: CloudTrail을 CEM으로 정규화하고 C-/D-Taint 전파 및 교차점을 계산

## 최초 실행

BackgroundBot 역할이 새로 추가되었으므로 기존 배포 후 한 번 더 적용한다.

```powershell
terraform plan -out=tfplan
terraform apply tfplan
```

PowerShell 정책이 로컬 스크립트 실행을 막는 경우 현재 프로세스에만 허용한다.

```powershell
Set-ExecutionPolicy -Scope Process Bypass
```

정상 대조군을 실행한다.

```powershell
.\scripts\invoke-background.ps1 -Iterations 5 -IntervalSeconds 5
```

마지막 줄에 출력된 manifest를 검증한다.

```powershell
.\scripts\verify-run.ps1 -ManifestPath ".\runs\background-YYYYMMDD-HHMMSS\manifest.json"
```

PASS 후 S1-a를 실행하고 같은 방식으로 검증한다.

```powershell
.\scripts\invoke-s1a.ps1
.\scripts\verify-run.ps1 -ManifestPath ".\runs\s1a-YYYYMMDD-HHMMSS\manifest.json"
.\scripts\analyze-run.ps1 -ManifestPath ".\runs\s1a-YYYYMMDD-HHMMSS\manifest.json"
```

S2는 씨앗 없이 동일한 중요 데이터 계보를 이동시켜 D-only 경로를 측정한다.

```powershell
.\scripts\invoke-s2.ps1
.\scripts\verify-run.ps1 -ManifestPath ".\runs\s2-YYYYMMDD-HHMMSS\manifest.json"
.\scripts\analyze-run.ps1 -ManifestPath ".\runs\s2-YYYYMMDD-HHMMSS\manifest.json"
```

## Manifest 의미

- `steps`: 실행기가 실제 호출한 단계와 성공·실패
- `expected_events`: CloudTrail에서 반드시 복원되어야 하는 이벤트
- `forbidden_events`: 해당 window에 존재하면 안 되는 이벤트
- `verification.json`: CloudWatch 원본과 대조한 PASS/FAIL 및 eventID

Manifest는 평가 정답지이며 Taint 엔진 입력이 아니다. 엔진은 CloudTrail/CEM만 사용하고, 실행 후 결과를 manifest와 비교한다.

## 안전 경계

- 모든 객체는 합성 데이터다.
- BackgroundBot에는 `normal/*` 이외의 S3 권한이 없다.
- S1-a는 실제 IAM access key를 생성하지 않는다.
- R3와 R4는 기본 실행기에서 제외되어 있다.
- 실행기가 실패해도 원래 AWS credential 환경을 복원하고 임시 파일을 삭제한다.
- `runs/`는 Git에서 제외한다.
