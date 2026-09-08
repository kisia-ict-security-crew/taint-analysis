# C-/D-Taint 침해 영향 추적 핵심 설계

상태: 논문과 구현의 최우선 기준 문서

## 1. 이 연구가 답하려는 질문

이 연구의 질문은 “공격이 있었는가?” 하나가 아니다.

```text
C-Taint: 공격자의 영향이 어디까지 이어졌는가?
D-Taint: 중요한 데이터가 어디에 있고 어디로 이동했는가?
C∩D:    공격자의 영향이 중요한 자산에 실제로 닿은 최초 지점은 어디인가?
```

기존 AWS 실행 경로를 변경하지 않고 HoneyToken, 중요 자산 registry와 감사 로그를 이용해 이 세 질문에
답한다. Taint는 업무 데이터 안에 넣는 표식이 아니라 원본 로그에서 파생해 외부 상태에 보존하는 분석
메타데이터다.

## 2. C, D, 교차점은 서로 대체할 수 없다

| 분석 | 혼자서 알 수 있는 것 | 혼자서는 알 수 없는 것 |
|---|---|---|
| C만 분석 | HoneyToken 접촉 이후 세션·권한 위임·행위 등 침해 영향 경로 | 그 경로가 중요 데이터나 핵심 자산에 닿았는지 |
| D만 분석 | 중요 데이터의 접근·복사·파생 후보와 정상 업무 흐름 | 그 흐름이 공격자에 의한 것인지 정상 ETL·백업인지 |
| C∩D 분석 | 침해 계보와 중요 자산 계보가 만난 구체적 행위와 최초 시점 | 로그 밖에서 일어난 행위 또는 HoneyToken을 전혀 거치지 않은 공격 |

C만으로도 침해 영향을 알 수 있다. 예를 들어 C 세션이 IAM 정책을 바꾸거나 인스턴스를 삭제했다면 이는
중요 데이터와 무관하더라도 분명한 제어권·가용성 영향이다. 그러므로 C-only를 무시하면 안 된다.

D만으로도 중요 데이터 흐름을 알 수 있다. 정상 백업, 분석 작업, 복사 경로를 파악할 수 있으므로 데이터
거버넌스에 유용하다. 하지만 D-only는 악성 행위의 증거가 아니다.

교차점은 C와 D를 대신하는 세 번째 탐지기가 아니다. 두 독립 질문을 결합해 “침해가 중요한 자산에
미친 실현된 영향”을 우선순위화하는 판정이다.

## 3. 가장 중요한 의미 구분

### 3.1 C-Taint: 침해·제어 계보

C는 `이 주체 또는 행위가 고신뢰 침해 시작점의 영향을 받았는가`를 나타낸다.

- 시작점: 성공한 HoneyToken 취득, 사용된 decoy credential, 또는 별도로 확정된 침해 세션
- 기본 대상: credential instance, session, invocation, process 같은 실행 주체
- 전파: 로그에 parent→child 제어 관계가 직접 있을 때
- footprint: C 주체가 생성·수정·삭제한 리소스에는 C 영향 흔적을 남김
- 금지: 같은 IAM Role, IP, user-agent, 계정 또는 가까운 시간만으로 C를 전파하지 않음

C는 “악성이라고 완전히 확정”이라는 뜻이 아니다. 보안 scanner나 관리자 시험이 HoneyToken을 건드릴
수 있으므로 seed 유형과 신뢰도를 함께 저장한다.

### 3.2 D-Taint: 중요 데이터 계보

D는 `이 데이터 객체가 보호 대상 데이터이거나 그 데이터에서 직접 유래했는가`를 나타낸다.

- 시작점: registry에 등록한 중요 S3 object version, secret version, DB object 등
- 기본 대상: 데이터를 담는 versioned object, message, artifact, row/record
- 전파: CopyObject처럼 source→destination 데이터 관계가 직접 보일 때
- 노출: 세션이 D 객체를 읽으면 `D-EXPOSURE(session, data)` 관계를 기록
- 금지: D 객체를 읽은 세션 자체를 데이터 객체처럼 취급해 모든 후속 출력에 E1 D를 퍼뜨리지 않음

중요 객체의 정상 읽기도 D exposure다. D는 악성 여부가 아니라 데이터의 중요성과 이동 관계를 나타낸다.

D 내부에서도 두 의미를 분리한다.

- `D-CLASSIFIED`: 중요 버킷 경로, secret, DB table처럼 보호 대상으로 지정된 논리 자산
- `D-LINEAGE`: 특정 중요 데이터 version에서 직접 복사·파생된 데이터 version

예를 들어 공격자가 중요 S3 key를 새로운 값으로 덮어쓰면 새 내용이 기존 D에서 파생됐다고 볼 수는
없다. 하지만 `D-CLASSIFIED` 자산을 C 주체가 변경했으므로 `WRITE` 무결성 교차점은 성립한다. 반대로
중요 객체를 다른 key로 복사하면 destination은 `D-LINEAGE`가 된다. 이 구분으로 자산 중요도와 데이터
내용의 계보를 혼동하지 않는다.

### 3.3 교차점: 중요 자산에 대한 침해 영향

교차점은 단순히 어떤 엔터티에 C와 D Boolean이 동시에 존재하는 상태가 아니다. 다음 조건을 만족하는
`행위 edge`다.

```text
Intersection(event) = C(actor)
                    AND D(relevant data/resource)
                    AND impact-relevant action(event)
```

즉 C 주체가 D 자산을 읽거나, 수정하거나, 삭제하거나, 명시적으로 복사한 사건이 교차점이다.

## 4. 왜 최초 교차점을 보는가

최초 교차점 이전에는 “침해 흔적은 있지만 중요 자산 영향은 아직 확인되지 않은 상태”다. 최초 교차점에서
처음으로 공격 계보와 사업상 중요한 자산이 하나의 직접 증거로 연결된다.

최초 교차점은 다음 네 가지를 제공한다.

1. **영향 확인:** 단순한 침해 가능성에서 기밀성·무결성·가용성 영향 조사로 전환할 근거가 된다.
2. **대응 우선순위:** 모든 C-only 행위와 모든 D-only 정상 흐름보다 먼저 확인할 사건을 좁힌다.
3. **조사 기준점:** 교차점 이전에는 침입 경로를 역추적하고, 이후에는 영향받은 데이터 계보를 순방향 추적한다.
4. **대응 시간 측정:** HoneyToken 접촉부터 중요 자산 영향까지의 `time-to-impact`를 계산할 수 있다.

교차점은 공격 성공이나 외부 유출의 자동 확정이 아니다. 어떤 동작에서 교차했는지에 따라 주장 범위가
달라진다.

## 5. 교차점 유형과 의미

| 유형 | 조건 | 확인 가능한 영향 | 아직 확인할 수 없는 것 |
|---|---|---|---|
| `READ` | C 세션이 D 객체를 성공적으로 읽음 | 기밀성 노출 가능성 | 외부 반출·실제 내용 열람 |
| `WRITE` | C 세션이 기존 D 자산을 수정 | 무결성 훼손 가능성 | 실제 값이 악성인지 여부 |
| `DELETE` | C 세션이 D 자산/version을 삭제 | 가용성 훼손 | 복구 불가능 여부 |
| `COPY` | C 세션이 D source를 명시적으로 복사 | D 계보 확산, 반출 준비 가능성 | 외부 유출 완료 여부 |
| `DERIVE` | C 실행이 D 입력으로 새 출력을 생성 | 파생 데이터 영향 | 로그만으로 데이터 의존이 안 보이면 E2 |
| `EGRESS` | C 주체의 D 출력과 외부 목적지가 연결 | 유출 후보 | 네트워크 메타데이터만 있으면 D 포함 여부 |
| `CONTROL` | C 주체가 D 접근 가능 workload·policy를 장악 | 잠재 영향·권한 경로 | 실제 D 접근은 아님 |

논문의 주 결과에는 `READ`, `WRITE`, `DELETE`, 명시적 `COPY`의 E1 교차점을 사용한다. `DERIVE`,
`EGRESS`, `CONTROL`은 필요한 직접 증거가 없으면 E2 후보 또는 E3 위험으로 분리한다.

## 6. C-only, D-only, C∩D를 모두 유지하는 이유

```text
C-only
  → 침해 확산·권한 장악·비중요 리소스 훼손 조사

D-only
  → 정상 또는 미분류 주체의 중요 데이터 흐름·거버넌스 조사

C∩D
  → 침해 주체가 중요 자산에 미친 실현된 영향의 우선 조사
```

경보 우선순위는 다음처럼 사용한다.

| 우선순위 | 조건 | 대응 |
|---|---|---|
| P0 | E1 C∩D `READ/WRITE/DELETE/COPY` | 즉시 incident triage, 세션 차단·증거 보존 검토 |
| P1 | E2 C∩D `DERIVE/EGRESS` | 추가 로그로 검증 후 대응 |
| P2 | C-only의 권한 변경·지속성·삭제 | 침해 확산 조사 |
| P3 | D-only의 비정상 경로·대량 접근 | 정상 업무 여부와 미탐 C 가능성 조사 |

따라서 교차하지 않았다는 이유로 C-only와 D-only를 안전하다고 판단하지 않는다. HoneyToken을 우회한
공격은 D-only로 보일 수 있고, 데이터에 접근하지 않은 파괴 행위는 C-only로 남을 수 있다.

## 7. 최소 전파 규칙

복잡성을 줄이기 위해 메인 엔진은 여섯 규칙만 가진다.

| 규칙 | 조건 | 결과 |
|---|---|---|
| `C-SEED` | 등록 HoneyToken을 구체적 세션이 성공적으로 취득 | 그 세션에 C 원인 추가 |
| `C-CONTROL` | C 주체와 새 실행 주체 사이의 직접 parent→child 관계 | child에 C 원인 합집합 |
| `C-FOOTPRINT` | C 주체가 리소스를 생성·수정·삭제 | 행위와 리소스에 C 영향 흔적 |
| `D-SEED` | 등록 중요 논리 자산·데이터 version | D-CLASSIFIED/D-LINEAGE 원인 추가 |
| `D-COPY` | D source→destination 관계가 이벤트에 명시 | destination에 D 원인 합집합 |
| `IMPACT` | C actor가 D 자산에 영향 동작 수행 | typed C∩D 교차점 기록 |

`Get→transform→Put`, Lambda 내부 처리, 메시지 payload, DB row 변환처럼 source→destination이 로그에
직접 없으면 E1 상태를 변경하지 않는다. 필요한 경우 E2 후보 edge만 만든다.

## 8. 증거 등급

| 등급 | 의미 | 예시 |
|---|---|---|
| `E1 EXACT` | 직접 식별자 또는 source→destination이 로그에 존재 | STS 발급 세션, S3 CopyObject |
| `E2 INFERRED` | 동일 실행 단위·제한 시간창으로 추론 | GetObject 후 같은 세션의 PutObject |
| `E3 OBSERVED` | 시도·접근·권한 변경 사실만 관측 | AccessDenied, List, policy 변경 |
| `U UNSUPPORTED` | 필요한 경계가 로그에 없음 | 메모리·파일 byte·DB row 내부 흐름 |

E2 결과가 이후 E1 전파의 입력이 되지 않게 상태를 분리한다. 그렇지 않으면 한 번의 추정이 전체 계보를
정확한 사실처럼 오염시킨다.

## 9. 상태와 저장

```text
원본 증거 S3
  └─ 변경하지 않은 CloudTrail·서비스 로그와 digest

Taint 상태 저장소
  ├─ C subject state: session/invocation/process별 C seed 집합
  ├─ D object state: object/message/artifact version별 D seed 집합
  ├─ exposure edge: 어떤 subject가 어떤 D를 읽었는지
  ├─ footprint edge: 어떤 C subject가 어떤 자산에 무엇을 했는지
  └─ first intersection: C seed × D seed별 최초 typed impact edge
```

리소스 태그는 선택적 화면 표시일 뿐 권위 상태가 아니다. 원문 credential, secret, token, payload는 상태
저장소에 넣지 않고 credential은 fingerprint로 바꾼다.

같은 엔터티 생애에서 원인 집합은 합집합으로만 증가한다. 자격증명 만료나 객체 삭제는 이력을 없애지
않는다. 다만 새 object version, 새 session, 새 process는 별도 엔터티이므로 과거 Taint를 무조건 물려받지
않는다.

## 10. Taint 훼손·회피 위협과 방어

| 위협 | 잘못 설계했을 때 | 방어 원칙 |
|---|---|---|
| 로그 삭제·수정 | 근거와 Taint를 함께 제거 | 별도 로그 계정, KMS, versioning/Object Lock 선택, CloudTrail digest 검증 |
| 상태 DB 삭제·False reset | 침해 계보 세탁 | append-only edge, 조건부 union, 정정은 superseding record |
| label laundering | copy·rename·재암호화로 D 제거 | 명시적 source→destination이면 D 유지; 불명확하면 E2/U |
| 새 자격증명으로 전환 | 기존 C 연결 단절 | 직접 발급 edge가 있을 때만 전파; 없으면 coverage gap 공개 |
| 고의 HoneyToken 접촉 | C를 대량 확산시켜 경보 마비 | credential instance 단위 C, IP/role 기반 확산 금지, seed 유형·rate 기록 |
| 공유 role 오염 | 정상 작업 전체가 C가 됨 | role이 아닌 실제 session 식별 |
| Taint explosion | 상태·조사량 무한 증가 | seed reference와 edge dedup/요약; 원인 근거를 조용히 삭제하지 않음 |
| 로그 지연·순서 변경 | child/교차 누락 | eventID dedup, watermark, late-event 재전파 |
| 로그 미수집 | “교차 없음”으로 오판 | `NO_COVERAGE`로 분리, negative result 금지 |
| selector·Trail 중지 | 이후 행위 은닉 | 설정 변경 자체를 별도 무결성 경보로 수집 |

CloudTrail log file validation은 전달 후 로그의 수정·삭제 탐지 근거를 제공하지만, 기능 활성화만으로
검증이 완료되는 것은 아니다. 실험 종료 후 실제 validation 결과를 보존한다.

## 11. 시스템 구조

```text
기존 AWS 워크로드와 API
            │
            ▼
CloudTrail 관리 이벤트 + 선택된 data event + 필요한 서비스 로그
            │
            ├── 원본 증거 S3
            ▼
      CEM 정규화·중복 제거
            ▼
   6개 규칙 기반 Taint 엔진
            ▼
 C state / D state / exposure / footprint / typed intersection
            ▼
      P0~P3 보고서와 경보
```

메인 구조는 비동기 로그 분석이다. 분석 장애가 기존 업무 요청을 막지 않는다. 세부 서비스별 로그,
성공·실패·batch·retry·추가 계측 규칙은
[리소스·상황별 구현 부록](TAINT_RESOURCE_LOG_IMPLEMENTATION_MATRIX.md)을 따른다.

## 12. 비용 목적

최소비용의 핵심은 모든 데이터 이동을 완벽하게 추적하는 것이 아니라, 희소한 C seed와 중요한 D seed를
기준으로 조사 가치가 높은 교차점을 좁히는 것이다.

```text
C_total = 기존 관리 로그
        + 선택한 Honey/중요 자산 data event
        + 실제 C/D 상태 변화
        + 최초 교차점 처리·보존
```

전체 계정의 모든 데이터 이벤트를 수집하지 않는다. 기존 관리 로그를 재사용하고, 유료 data event는
HoneyToken과 중요 자산 범위로 제한한다. 원본 로그는 S3에 두고 모든 이벤트를 별도 검색 DB에 복제하지
않으며, 바뀐 상태와 교차점만 저장한다.

## 13. 이 핵심 가설을 검증하는 실험

### 13.1 비교 실험

동일 정답지에서 네 분석 결과를 비교한다.

| 실험군 | 입력 label | 확인할 것 |
|---|---|---|
| A | C만 | 침해 경로 recall, 중요 영향과 무관한 후보 수 |
| B | D만 | 중요 흐름 coverage, 정상 업무 후보 수 |
| C | C+D지만 교차 우선순위 없음 | 두 결과를 단순 합쳤을 때 조사량 |
| D | typed C∩D | 실제 중요 영향 precision, 조사량 감소, time-to-impact |

교차의 필요성은 주장으로 정하지 않고 다음 값으로 증명한다.

```text
Precision_C       = 실제 침해 행위 / C 후보
Precision_D       = 실제 중요 영향 행위 / D 후보
Precision_X       = 실제 중요 침해 영향 / typed C∩D 후보
Reduction_X       = 1 - (typed C∩D 후보 / C와 D 전체 조사 후보)
Recall_X          = 찾은 중요 침해 영향 / 정답 중요 침해 영향
Time_to_impact    = first_intersection_time - C_seed_time
```

`Precision_X`와 조사량만 좋아지고 `Recall_X`가 크게 떨어지면 성공으로 판정하지 않는다.

### 13.2 필수 시나리오

| ID | 시나리오 | 기대 분류 |
|---|---|---|
| B0 | Honey와 중요 자산에 닿지 않는 정상 행위 | clean |
| C1 | Honey 접촉 후 일반 조회 | C-only |
| C2 | Honey 접촉 후 IAM 변경·일반 자산 삭제 | C-only control/availability impact |
| D1 | 정상 backup/ETL의 중요 데이터 읽기·복사 | D-only |
| X1 | C 세션의 중요 객체 읽기 | E1 C∩D READ |
| X2 | C 세션의 중요 객체 수정 | E1 C∩D WRITE |
| X3 | C 세션의 중요 객체 삭제 | E1 C∩D DELETE |
| X4 | C 세션의 명시적 중요 객체 복사 | E1 C∩D COPY |
| X5 | 중요 GET 후 앱 변환·PUT | E2 DERIVE 후보 |
| N1 | 거부된 Honey 접근 | E3, C-success 없음 |
| N2 | 같은 IP·role의 독립 세션 | C 전파 없음 |
| N3 | Honey를 우회한 공격자의 중요 데이터 접근 | D-only 이상; 교차 기반 미탐 한계로 집계 |
| T1 | tag 삭제·상태 reset 시도 | 권위 이력 유지·훼손 경보 |
| T2 | late/out-of-order 로그 | 재처리 후 같은 최초 교차점 |

### 13.3 통과 기준

- C-only, D-only, 교차를 정답 시나리오와 일치하게 분리한다.
- N1·N2를 E1 C 또는 E1 교차로 잘못 올리지 않는다.
- X1~X4의 교차 유형과 최초 eventID를 정확히 찾는다.
- X5를 E1로 과장하지 않는다.
- N3을 “안전”으로 쓰지 않고 C seed coverage 한계로 보고한다.
- 상태·tag 훼손 뒤에도 원본 근거와 append-only edge를 복구할 수 있다.
- C-only, D-only 대비 typed 교차의 precision·recall·후보 수를 함께 제시한다.
- 전체 수집 대비 선택 수집의 비용과 관측 coverage를 함께 제시한다.

## 14. 현재 구현과 남은 핵심 작업

공식 구현은 `infrastructure/aws/`다. CloudTrail, 합성 Honey/중요 객체, STS 역할 전환, S3 로그 수집,
CEM과 초기 C/D 분석기가 있다.

현재 코드 대조 결과는 다음과 같다.

| 항목 | 상태 | 검증 근거 |
|---|---|---|
| 성공한 Honey 접촉만 C 생성 | 구현 | 성공 seed 테스트와 AccessDenied 음성 테스트 |
| 순수 Honey는 D가 아님 | 구현 | Honey-only가 `C_ONLY`인지 확인하는 회귀 테스트 |
| STS parent→child C 전파 | 구현 | actor A→B→C session 테스트 |
| 중요 객체와 Honey seed 분리 | 구현 | D seed를 critical object로만 구성 |
| 명시적 S3 CopyObject D 전파 | 구현 | critical→staging→egress 테스트 |
| D-only 정상/미분류 흐름 | 구현 | C seed 없는 S2 테스트 |
| typed `READ` 교차 | 부분 구현 | `C_READS_D` edge는 있으나 최초 교차 전용 상태는 없음 |
| `WRITE/DELETE/COPY` 교차 유형 분리 | 미구현 | 현재는 사건별 typed impact 결과가 없음 |
| D-class와 D-lineage 분리 저장 | 미구현 | 현재 D resource 집합은 하나로 축약됨 |
| E1/E2/E3/U 분리 | 미구현 | 현재 출력은 대부분 EXACT 축약 표현 |
| Taint 훼손·late-event 통합 실험 | 미구현 | 설계와 시험 시나리오만 존재 |

다음 작업만 우선 수행한다.

1. Boolean C/D를 `c_sources`, `d_sources` 원인 집합으로 변경한다.
2. D를 데이터 객체에만 부착하고 session에는 exposure edge를 기록한다.
3. 모든 판정에 E1/E2/E3/U와 원본 eventID를 기록한다.
4. `READ/WRITE/DELETE/COPY` typed intersection과 최초 edge를 구현한다.
5. C-only/D-only/C∩D ablation 및 T1/T2 훼손 실험을 자동화한다.
6. 전체 data event와 선택 data event의 비용·coverage를 비교한다.

Lambda 내부, 메시지 payload, DB row, 프로세스 byte 흐름은 이 핵심 검증이 끝난 뒤 필요한 경계만
선택적으로 계측한다. 많은 서비스를 얕게 지원하는 것보다 STS+S3에서 C, D, 교차의 의미와 효과를
정확히 입증하는 것을 우선한다.

## 15. 논문이 최종적으로 주장할 수 있는 것

결과가 통과하면 다음 범위로 주장한다.

> C-Taint는 고신뢰 침해 시작점 이후의 제어 영향을, D-Taint는 중요 데이터의 위치와 명시적 이동을
> 각각 추적한다. 두 계보의 typed intersection은 침해 주체가 중요 자산에 읽기·수정·삭제·복사 영향을
> 준 최초 감사 이벤트를 식별한다. 이 결합은 C-only와 D-only 분석을 대체하지 않으며, 중요 침해 영향의
> 조사 우선순위를 좁히는 데 사용된다. 로그가 직접 인과관계를 제공하지 않는 경계는 추정 또는 미지원으로
> 분리한다.

SLEUTH가 신뢰도와 기밀성 tag를 분리해 감사 provenance에서 공격 탐지와 영향 분석에 활용한 것처럼,
서로 다른 의미의 label을 분리하는 것이 후보 축소와 설명 가능성에 중요하다. 본 연구의 차별점은 이를
HoneyToken 기반 C 계보와 클라우드 중요 데이터 D 계보로 제한하고, 저비용 선택 수집과 최초 typed
교차점 평가에 집중하는 것이다.

참고:

- [SLEUTH: Real-time Attack Scenario Reconstruction from COTS Audit Data](https://sisl-lab.red.uic.edu/wp-content/uploads/sites/330/2018/07/SLEUTH.pdf)
- [NIST의 기밀성·무결성·가용성 기반 impact 정의](https://csrc.nist.gov/glossary/term/impact)
- [CloudTrail log file integrity validation](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html)
