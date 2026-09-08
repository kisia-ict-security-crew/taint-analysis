# 보관된 강제 중개 비용 예비 결과

> **현재 저비용 설계의 평가 결과가 아닙니다.** 이 실험은 최종 구조에서 제외한 요청 중개 구현을
> 측정했으며, 로그 기반 선택 수집의 비용 결과와 합산하거나 비교하지 않습니다.

실험일: 2026-09-08  
리전: AWS Asia Pacific (Seoul)  
범위: 단일 연구 계정, 합성 S3 객체와 임시 STS session  
판정: **PASS - 제한 범위 feasibility**

## 1. 실행한 실험

1. 로컬 Broker 단위 테스트 17개
2. 최신 registry 기반 Broker를 기존 AWS Lambda에 반영
3. B0 clean, S1 C∩D, S2 D-only, raw S3 우회 거부 통합 시험
4. 같은 공유 평면에 합성 지뢰를 0, 1, 10, 100, 1,000개까지 누적 설치
5. 독립 session HoneyToken 접촉 5회
6. 1-byte 직접 S3 PUT 20회와 clean Broker PUT 20회 비교
7. Source/derived correctness를 포함한 전체 Broker invocation의 Lambda REPORT 수집
8. 임시 지뢰 registry와 객체를 exact key/version으로 정리

실제 데이터, 외부 반출, 공개 버킷, 실제 credential honeytoken은 사용하지 않았다.

## 2. 정확성 결과

| Assertion | 결과 |
|---|---|
| 독립 HoneyToken 접촉 5회가 모두 C 및 교차 생성 | PASS |
| clean Broker PUT 20회가 모두 `(C,D)=(0,0)` | PASS |
| S1 honey→delegate×2→critical copy가 `(1,1)` | PASS |
| S2 independent critical read→put이 `(0,1)` | PASS |
| worker의 직접 S3 우회 | AccessDenied, PASS |
| 공유 Lambda와 API Gateway 수 불변 | PASS |
| Lambda REPORT 완전성 | 31/31, PASS |

재배포 직후 별도 B0/S1/S2 통합 실행도 7개 작업 전체 PASS였고 raw S3 우회가 거부됐다.

## 3. 지뢰 규모 결과

| 누적 지뢰 | 해당 단계 신규 DDB write | 신규 S3 PUT | 공유 Lambda | API Gateway | 상태 table |
|---:|---:|---:|---:|---:|---:|
| 0 | 0 | 0 | 1 | 1 | 1 |
| 1 | 1 | 1 | 1 | 1 | 1 |
| 10 | 9 | 9 | 1 | 1 | 1 |
| 100 | 90 | 90 | 1 | 1 | 1 |
| 1,000 | 900 | 900 | 1 | 1 | 1 |

지뢰 1,000개에서도 새로운 Lambda, API Gateway, table은 생성되지 않았다. 설치는 지뢰당 DynamoDB write 1회와 S3 PUT 1회였고 Broker invocation은 0이었다. 따라서 이 구현 범위에서 지뢰 수 N과 상시 컴퓨팅 리소스 수를 분리했다.

설치 시간은 병렬 요청과 cold/warm 상태의 영향을 받아 단조적이지 않았으므로 비용 또는 성능 결론에 사용하지 않는다.

실험 후 정리 확인:

- 임시 mine registry: 0건
- `cost-study/` S3 object version: 0건
- Broker의 파생 객체와 상태는 연구 증거로 보존

## 4. 지연 측정

| 작업 | n | 평균 | p50 | p95 | 최소 | 최대 |
|---|---:|---:|---:|---:|---:|---:|
| HoneyToken 접촉 | 5 | 493.23 ms | 503.49 ms | 507.38 ms | 467.27 ms | 507.38 ms |
| 직접 S3 PUT | 20 | 32.81 ms | 31.48 ms | 41.68 ms | 28.60 ms | 45.67 ms |
| 보호 Broker PUT | 20 | 649.93 ms | 462.38 ms | 818.56 ms | 435.01 ms | 3,556.97 ms |

Broker PUT 최대값에는 cold start가 포함됐다. 실험 시간창의 Lambda REPORT는 31/31개였고 다음과 같다.

| Lambda 지표 | 결과 |
|---|---:|
| 평균 handler duration | 555.65 ms |
| p50 handler duration | 437.20 ms |
| p95 handler duration | 795.05 ms |
| 평균 billed duration | 559.42 ms |
| cold start | 1/31 |
| memory | 256 MB |

현재 Broker는 비용보다 정확성을 우선한 전역 lease 구조이므로 직접 S3 대비 지연이 크다. 이는 모든 정상 요청을 중개하면 안 된다는 설계를 지지한다.

## 5. 서울 리전 bottom-up 비용 추정

실험일 AWS Price List API에서 확인한 첫 사용량 구간 단가:

| 항목 | 단가 |
|---|---:|
| Lambda request | $0.20 / 1M |
| Lambda x86 duration | $0.0000166667 / GB-s |
| REST API Gateway | $3.50 / 1M |
| DynamoDB on-demand read unit | $0.1355 / 1M |
| DynamoDB on-demand write unit | $0.68 / 1M |
| S3 Standard PUT | $0.0045 / 1,000 |
| S3 Standard GET | $0.0035 / 10,000 |

무료 구간, 데이터 전송, CloudWatch Logs 저장, DynamoDB/S3 장기 저장, PITR, KMS 고정비는 제외했다. 아래 값은 청구서가 아니라 관측 API 수와 billed duration을 사용한 변동비 추정이다.

### 지뢰 설치

지뢰 1,000개 설치의 최초 요청 비용:

```text
1,000 DDB write + 1,000 S3 PUT ≈ $0.00518
```

이는 일회성 설치 요청 비용이다. 객체와 registry의 월 저장비 및 보존 정책은 장기 실험에서 별도로 측정해야 한다. 이번 정리 과정의 DDB delete 비용은 연구 실행 비용이며 운영 설치 비용에서 제외한다.

### Broker 실행

코드 경로의 구조적 meter는 31개 Broker 요청에서 약 140 read unit, 124 write unit, S3 GET 8회, Broker S3 PUT 22회다. 관측 billed duration을 결합한 변동비는 약 다음과 같다.

```text
31개 Broker 요청 ≈ $0.000392
clean Broker PUT 1회 ≈ $0.00001379
direct S3 PUT 1회 ≈ $0.00000450
Broker의 추가 변동비 ≈ $0.00000929 / protected operation
```

HoneyToken 접촉은 약 $0.00000964/회로 추정된다. 접촉이 희소하다는 지뢰 가정에서는 절대 비용이 작지만, 정상 요청 전체를 Broker로 통과시키면 누적된다.

## 6. 선택적 중개의 비용 효과

동일한 1-byte PUT 100만 회를 가정하고 이번 평균 billed duration과 첫 구간 단가를 적용했다.

| Broker 적용 비율 P/Q | 예상 변동비 | 모든 요청 Broker 대비 감소 |
|---:|---:|---:|
| 0.1% | 약 $4.51 | 약 $9.28 |
| 1% | 약 $4.59 | 약 $9.20 |
| 10% | 약 $5.43 | 약 $8.36 |
| 100% | 약 $13.79 | 기준 |

이 계산은 payload가 매우 작은 현재 실험에 한정된다. 그래도 비용 목적은 명확하다. Broker가 직접 API보다 싸기 때문이 아니라, `P << Q`가 되도록 지뢰·중요 데이터·반출 경계만 보호하기 때문에 full mediation 비용을 피한다.

## 7. 결론

이번 실험으로 다음을 직접 확인했다.

1. 지뢰 1,000개까지 공유 컴퓨팅 리소스 수가 증가하지 않았다.
2. 지뢰 설치 중 Broker 실행은 없었고 설치 요청은 지뢰당 DDB write 1회와 S3 PUT 1회였다.
3. C/D 전파, 최초 교차, D-only 분리와 직접 우회 거부가 모두 동작했다.
4. Broker는 직접 S3보다 느리고 비싸므로 전체 경로 적용은 저비용 목적에 맞지 않는다.
5. 보호 요청 비율을 1%로 제한한 계산에서는 full Broker 대비 약 $9.20/100만 전체 PUT의 변동비를 줄였다.

따라서 현재 결과는 “공유 지뢰의 낮은 한계 설치비”와 “선택적 중개의 필요성”에 대한 feasibility 근거다. 월 총비용 우위와 통계적 성능을 주장하려면 24시간 이상 idle 측정, 조건별 반복, 실제 Q/P 분포, CUR/Cost Explorer 대조가 필요하다.

## 8. 재현성과 한계

- 실험 실행기: `infrastructure/runtime/run_cost_study.py`
- 공식 단가 스냅샷 도구: `infrastructure/runtime/pricing_snapshot.py`
- 원시 정제 결과: `infrastructure/runtime/results/latest-cost-study.json`
- 설계서: `LOW_COST_TAINT_DESIGN.md`
- 기존 runtime Terraform의 로컬 state가 없어 이번에는 기존 AWS 리소스를 이름으로 검증한 뒤 Lambda 코드와 두 registry 항목을 직접 갱신했다. 후속 IaC 실행 전에 state import 또는 새 backend가 필요하다.
- 표본은 direct/Broker PUT 각 20회, 접촉 5회, Lambda 31회뿐이다. p95와 비용 일반화에는 부족하다.
