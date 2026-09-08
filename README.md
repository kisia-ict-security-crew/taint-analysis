# taint-analysis

기존 클라우드 실행 경로를 변경하지 않고 HoneyToken 접촉의 C-Taint와 중요 데이터의 D-Taint를
감사 로그에서 재구성하여 최초 교차점을 찾는 연구 프로젝트입니다. 목표는 전체 워크로드에 보안 구성요소를
삽입하는 것이 아니라, 지뢰와 중요 자산에 한정한 로그 수집·상태 전이로 조사 범위를 줄이는 것입니다.

## 연구 기준 문서

- [CISC 제출용 연구·실험 설계](CISC_SUBMISSION_RESEARCH_DESIGN.md)
- [C-/D-Taint 목적·교차점·검증을 포함한 핵심 설계](RESEARCH_REDESIGN.md)
- [AWS 리소스·로그·상황별 구현 부록](TAINT_RESOURCE_LOG_IMPLEMENTATION_MATRIX.md)
- [로그 기반 저비용 평가 설계](LOW_COST_TAINT_DESIGN.md)
- [논문 분석과 구현 공백](PAPER_REVIEW_AND_INTEGRATION.md)
- [AWS IaC·실험 환경](infrastructure/aws/README.md)

## 핵심 구조

```text
기존 AWS API 활동
  → CloudTrail 관리 이벤트 + 선택된 S3 데이터 이벤트
  → CEM 정규화
  → 단조 C-/D-Taint 상태·계보
  → E1/E2/E3/U 증거 수준별 최초 C∩D 교차점
  → 보고서·경보
```

Taint는 업무 데이터에 삽입하지 않고 별도 분석 상태로 저장합니다. 성공한 HoneyToken 접촉은 구체적인
세션에 C를 만들고, 등록된 중요 객체는 D seed가 됩니다. STS 발급 관계와 S3 CopyObject처럼 로그에
직접 관계가 있는 전파는 `E1 EXACT`, 같은 세션의 read→write처럼 데이터 의존을 직접 볼 수 없는 관계는
`E2 INFERRED`, 접근 사실만 있는 경우는 `E3 OBSERVED`, 판정할 수 없는 경계는 `U UNSUPPORTED`로
분리합니다.

## 프로젝트 구조

```text
taint-analysis/
├─ infrastructure/
│  ├─ aws/          # 공식 IaC, 로그 수집, 시나리오, Taint 분석기
│  ├─ azure/        # 조사 단계
│  ├─ gcp/          # 조사 단계
│  ├─ ncloud/       # 조사 단계
│  └─ runtime/      # 최종 아키텍처에 포함되지 않는 과거 예비 구현
├─ RESEARCH_REDESIGN.md
└─ LOW_COST_TAINT_DESIGN.md
```

현재 검증된 범위는 AWS의 합성 S3 객체와 STS 세션을 이용한 제한된 실험입니다. Lambda 내부,
메시지 payload, DB row, 프로세스·파일·소켓 계보는 로그만으로 정확히 확인할 수 없으며 구현 완료로
간주하지 않습니다.

과거 예비 구현과 그 결과는 재현 기록을 위해 저장소에 남아 있지만 최종 논문의 제안 구조나 성능 근거로
사용하지 않습니다.
