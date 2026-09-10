# 多分野シナリオ評価レポート

> 固定fixtureと安全な合成JSONLを使い、カタログの全シナリオを同じ処理で再評価した結果です。
> 実マルウェア、攻撃ペイロード、外部ネットワークは使用していません。

## 集計

- シナリオ: **4件**
- trace paths: **4**
- mapping gaps: **0**
- generated Sigma candidates: **4**
- ATT&CK candidates before threat model: **4**
- applicable / blocked / unknown: **0 / 3 / 1**
- candidate reduction rate: **0.750**

## シナリオ別結果

| ID | 分野 | pipeline | outcome | before | applicable | blocked | unknown | coverage |
|---|---|---|---|---:|---:|---:|---:|---:|
| scenario-11-threat-model-blocked-no-flow | applicability_fixture | success | matched | 1 | 0 | 1 | 0 | 0.333 |
| scenario-12-threat-model-blocked-boundary | applicability_fixture | success | matched | 1 | 0 | 1 | 0 | 0.333 |
| scenario-13-threat-model-blocked-privilege | applicability_fixture | success | matched | 1 | 0 | 1 | 0 | 0.333 |
| scenario-14-threat-model-unknown-access | applicability_fixture | success | matched | 1 | 0 | 0 | 1 | 0.333 |

## 解釈上の注意

この評価は、公開知識から検知候補を生成できるかと、宣言したテレメトリの充足状況を測定します。
`attack_applicability`（攻撃適用可否）と`detection_feasibility`（検知可能性）は別の判定であり、
本レポートのcoverageは後者だけを表します。実環境ログや実攻撃への有効性は未評価です。
候補削減率は `blocked / before_candidate_count` とし、`unknown` は削減に含めません。
脅威モデル条件の境界値fixtureは、実脅威カタログとは分離して`scenarios/condition-fixtures.yaml`で評価します。
本カタログの6候補はすべてapplicableであり、ここでは候補削減効果は観測されません。
複数の公開脅威候補から対象システムに適用可能なものを選別する評価は、`threat-universe-results.json`で別途実施します。
blocked / unknown の理由は、通信経路、信頼境界、認証、認可、権限、権限遷移を区別して集計します。

## 理由別集計

- blocked: `{'communication_path': 1, 'privilege': 1, 'trust_boundary': 1}`
- unknown: `{'authentication': 1, 'authorization': 1, 'trust_boundary': 1}`
- detection feasibility: `{'detectable': 0, 'partial': 4, 'unavailable': 0, 'unknown': 0}`
