# 多分野評価レポート

> 固定fixtureと安全な合成JSONLだけを使った、10シナリオの再現可能な実測結果です。
> 実マルウェア、バイナリ、攻撃ペイロード、外部ネットワークは使用していません。

## 1. 評価方法

脆弱性、マルウェア挙動、認証・ID、ネットワーク、クラウド、対照の入口を、次の共通経路で評価しました。

```text
入口 → 弱点または挙動 → 攻撃者行動 → 監視対象 → 必要ログ → 検知候補
```

baselineは候補ルールなし、treatmentはこのパイプラインが生成したSigma候補です。数値は安全なJSONLイベントに対するイベント単位の結果であり、本番検知性能ではありません。

## 2. 全体集計

- シナリオ: **10件**
- pipeline status: `partial=3, success=7`
- entrypoint: `cloud_behavior=1, control=1, cve=2, identity_behavior=2, malware_behavior=3, network_behavior=1`
- analysis outcome: `control=1, matched=3, no_match=6`
- trace paths: **3**
- mapping gaps: **4**
- generated Sigma candidates: **3**
- telemetry coverage ratio（重複除去した項目）: **0.714**

## 3. 分野別比較

| 分野 | 件数 | pipeline | outcome | paths | gaps | Sigma | treatment実測 | coverage |
|---|---:|---|---|---:|---:|---:|---:|---:|
| cloud | 1 | success=1 | no_match=1 | 0 | 0 | 0 | 0 | 1.000 |
| control | 1 | success=1 | control=1 | 0 | 0 | 0 | 0 | 1.000 |
| identity | 2 | success=2 | no_match=2 | 0 | 0 | 0 | 0 | 1.000 |
| malware | 3 | partial=2, success=1 | matched=2, no_match=1 | 2 | 2 | 2 | 1 | 0.833 |
| network | 1 | success=1 | no_match=1 | 0 | 0 | 0 | 0 | 1.000 |
| vulnerability | 2 | partial=1, success=1 | matched=1, no_match=1 | 1 | 2 | 1 | 1 | 0.500 |

## 4. シナリオ別の実測結果

| ID | 分野 | entrypoint | outcome | pipeline | paths | gaps | required/available telemetry | coverage | Sigma |
|---|---|---|---|---|---:|---:|---:|---:|---:|
| scenario-01-cve-example-process | vulnerability | cve | matched | partial | 1 | 2 | 2/1 | 1.000 | 1 |
| scenario-02-cve-apache-counterexample | vulnerability | cve | no_match | success | 0 | 0 | 1/2 | 0.000 | 0 |
| scenario-03-malware-process-execution | malware | malware_behavior | matched | success | 1 | 0 | 2/1 | 1.000 | 1 |
| scenario-04-malware-ingress-transfer | malware | malware_behavior | no_match | partial | 0 | 1 | 2/1 | 0.500 | 0 |
| scenario-05-malware-staged-behavior | malware | malware_behavior | matched | partial | 1 | 1 | 3/2 | 1.000 | 1 |
| scenario-06-identity-credential-access | identity | identity_behavior | no_match | success | 0 | 0 | 1/1 | 1.000 | 0 |
| scenario-07-identity-authentication-anomaly | identity | identity_behavior | no_match | success | 0 | 0 | 1/1 | 1.000 | 0 |
| scenario-08-network-command-channel | network | network_behavior | no_match | success | 0 | 0 | 1/2 | 1.000 | 0 |
| scenario-09-cloud-control-plane | cloud | cloud_behavior | no_match | success | 0 | 0 | 1/1 | 1.000 | 0 |
| scenario-10-control-normal-administration | control | control | control | success | 0 | 0 | 1/1 | 1.000 | 0 |

## 5. baseline / treatment比較

| ID | baseline | treatment |
|---|---|---|
| scenario-01-cve-example-process | TP=0/FP=0/FN=1/TN=1 (P=None, R=0.0, F1=None) | TP=1/FP=0/FN=0/TN=1 (P=1.0, R=1.0, F1=1.0) |
| scenario-02-cve-apache-counterexample | TP=0/FP=0/FN=1/TN=1 (P=None, R=0.0, F1=None) | not_applicable: TechniqueまたはDetection Strategyが確定せず、Sigma候補が生成されなかった |
| scenario-03-malware-process-execution | TP=0/FP=0/FN=1/TN=1 (P=None, R=0.0, F1=None) | TP=1/FP=0/FN=0/TN=1 (P=1.0, R=1.0, F1=1.0) |
| scenario-04-malware-ingress-transfer | TP=0/FP=0/FN=1/TN=1 (P=None, R=0.0, F1=None) | not_applicable: TechniqueまたはDetection Strategyが確定せず、Sigma候補が生成されなかった |
| scenario-05-malware-staged-behavior | TP=0/FP=0/FN=1/TN=1 (P=None, R=0.0, F1=None) | not_applicable: 複数イベント相関を単一イベントmatcherで評価できないため、Sigma候補のTP/FPは算出しない |
| scenario-06-identity-credential-access | TP=0/FP=0/FN=1/TN=1 (P=None, R=0.0, F1=None) | not_applicable: TechniqueまたはDetection Strategyが確定せず、Sigma候補が生成されなかった |
| scenario-07-identity-authentication-anomaly | TP=0/FP=0/FN=1/TN=1 (P=None, R=0.0, F1=None) | not_applicable: TechniqueまたはDetection Strategyが確定せず、Sigma候補が生成されなかった |
| scenario-08-network-command-channel | TP=0/FP=0/FN=1/TN=1 (P=None, R=0.0, F1=None) | not_applicable: TechniqueまたはDetection Strategyが確定せず、Sigma候補が生成されなかった |
| scenario-09-cloud-control-plane | TP=0/FP=0/FN=1/TN=1 (P=None, R=0.0, F1=None) | not_applicable: TechniqueまたはDetection Strategyが確定せず、Sigma候補が生成されなかった |
| scenario-10-control-normal-administration | TP=0/FP=0/FN=1/TN=1 (P=None, R=0.0, F1=None) | not_applicable: TechniqueまたはDetection Strategyが確定せず、Sigma候補が生成されなかった |

### 集計値

- baseline実測シナリオ: **10件**
- treatment実測シナリオ: **2件**
- baseline confusion: `TP=0, FP=0, FN=10, TN=10`
- treatment confusion: `TP=2, FP=0, FN=0, TN=2`

## 6. 分かったことと限界

- CVEだけでなく、ATT&CK Techniqueを直接の入口にするマルウェア・認証・ネットワーク・クラウドのシナリオも、同じ監視要件・必要ログの形式で記録できました。
- 現行の小さなATT&CK fixtureではT1059/DET0001だけが候補生成まで到達し、T1105や他分野の未確定Techniqueは候補未生成として扱われました。
- treatmentのTP/FP/FN/TNは、単一イベントとして評価できるscenario-01/03だけを実測しています。scenario-05は候補自体は生成されますが、複数イベント相関を単一イベントmatcherで評価できないためnot_applicableです。候補未生成を0件の検知性能とは解釈していません。
- JSONLは安全な合成イベントです。実組織ログ、実マルウェア、実攻撃に対する有効性は未評価です。
- 次に必要なのは、各分野の出典付きsnapshot、フィールド定義、複数イベント相関、実環境または匿名化ログによる再評価です。

## 7. 集計成果物と再評価時の注意

集計結果は [`evaluations/multidomain-results.json`](multidomain-results.json) に保存しています。
今回の集計は、既存の10個のYAML、固定fixture、既存のSigma fixture matcherを使った一回の
offline実測です。再評価する場合は、同じ入力を使って各シナリオをCLI/パイプラインで実行し、
このJSONの各シナリオ記録と比較してください。

generic fields（`timestamp`、`event_id`、`source`、`message`）は保持したまま、scenario-01/03の
正例・負例にはSigma互換の `EventID` を追加しました。その結果、01/03は正例match、負例non-matchを
実測しています。scenario-05は複数イベント相関を必要とするため、単一イベントのTP/FPを捏造せず
not_applicableとしています。
