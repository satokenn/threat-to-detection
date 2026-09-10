# 多分野シナリオ評価レポート

> 固定fixtureと安全な合成JSONLを使い、カタログの全シナリオを同じ処理で再評価した結果です。
> 実マルウェア、攻撃ペイロード、外部ネットワークは使用していません。

## 集計

- シナリオ: **14件**
- trace paths: **7**
- mapping gaps: **4**
- generated Sigma candidates: **7**
- ATT&CK candidates before threat model: **10**
- applicable / blocked / unknown: **6 / 3 / 1**
- candidate reduction rate: **0.300**

## シナリオ別結果

| ID | 分野 | pipeline | outcome | before | applicable | blocked | unknown | coverage |
|---|---|---|---|---:|---:|---:|---:|---:|
| scenario-01-cve-example-process | vulnerability | partial | matched | 2 | 2 | 0 | 0 | 0.333 |
| scenario-02-cve-apache-counterexample | vulnerability | success | no_match | 0 | 0 | 0 | 0 | 0.000 |
| scenario-03-malware-process-execution | malware | success | matched | 1 | 1 | 0 | 0 | 0.250 |
| scenario-04-malware-ingress-transfer | malware | partial | no_match | 1 | 1 | 0 | 0 | 0.143 |
| scenario-05-malware-staged-behavior | malware | partial | matched | 2 | 2 | 0 | 0 | 0.250 |
| scenario-06-identity-credential-access | identity | success | no_match | 0 | 0 | 0 | 0 | 0.200 |
| scenario-07-identity-authentication-anomaly | identity | success | no_match | 0 | 0 | 0 | 0 | 0.167 |
| scenario-08-network-command-channel | network | success | no_match | 0 | 0 | 0 | 0 | 0.200 |
| scenario-09-cloud-control-plane | cloud | success | no_match | 0 | 0 | 0 | 0 | 0.143 |
| scenario-10-control-normal-administration | control | success | control | 0 | 0 | 0 | 0 | 0.250 |
| scenario-11-threat-model-blocked-no-flow | malware | success | matched | 1 | 0 | 1 | 0 | 0.333 |
| scenario-12-threat-model-blocked-boundary | malware | success | matched | 1 | 0 | 1 | 0 | 0.333 |
| scenario-13-threat-model-blocked-privilege | malware | success | matched | 1 | 0 | 1 | 0 | 0.333 |
| scenario-14-threat-model-unknown-access | malware | success | matched | 1 | 0 | 0 | 1 | 0.333 |

## 解釈上の注意

この評価は、公開知識から検知候補を生成できるかと、宣言したテレメトリの充足状況を測定します。
`attack_applicability`（攻撃適用可否）と`detection_feasibility`（検知可能性）は別の判定であり、
本レポートのcoverageは後者だけを表します。実環境ログや実攻撃への有効性は未評価です。
候補削減率は `blocked / before_candidate_count` とし、`unknown` は削減に含めません。
今回のblocked / unknownは、判定機構の境界条件を確認するための安全な合成fixtureを追加して測定しています。
この小規模なfixtureで削減率が観測されたことは、実環境での候補削減効果や一般化を示しません。
blocked / unknown の理由は、通信経路、信頼境界、認証、認可、権限、権限遷移を区別して集計します。

## 理由別集計

- blocked: `{'communication_path': 1, 'privilege': 1, 'trust_boundary': 1}`
- unknown: `{'authentication': 1, 'authorization': 1, 'trust_boundary': 1}`
- detection feasibility: `{'detectable': 0, 'partial': 7, 'unavailable': 0, 'unknown': 3}`
