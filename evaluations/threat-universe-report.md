# 脅威候補母集団の適用可否評価

> 公開ATT&CK Technique IDを参照した脅威候補母集団から、固定seedで層別抽出し、
> 対象システムの明示条件に照合したオフライン評価です。
> 実マルウェア、攻撃ペイロード、外部ネットワークは使用していません。

## 集計

- 母集団: **18件**
- 抽出候補: **12件**
- seed: **41**（domainごとに2件）
- applicable / blocked / unknown: **5 / 3 / 4**
- 候補削減率: **0.250**
- expected_outcome: **passed**

## 候補別結果

| Threat ID | domain | technique | target | status | reasons |
|---|---|---|---|---|---|
| universe-t1021-rdp-database | lateral_movement | T1021.001 | database | applicable | none |
| universe-t1021-ssh-database-blocked | lateral_movement | T1021.004 | database | blocked | communication_path |
| universe-t1046-database-blocked-boundary | discovery | T1046 | database | blocked | trust_boundary |
| universe-t1059-outbound-unknown | execution | T1059 | web-server | unknown | preconditions |
| universe-t1059-persistence-unknown | persistence | T1059 | web-server | unknown | preconditions |
| universe-t1071-http-applicable | command_and_control | T1071.001 | web-server | applicable | none |
| universe-t1105-ingress-applicable | execution | T1105 | web-server | applicable | none |
| universe-t1105-outbound-blocked | command_and_control | T1105 | web-server | blocked | communication_path |
| universe-t1135-database-applicable | discovery | T1135 | database | applicable | none |
| universe-t1190-public-applicable | initial_access | T1190 | web-server | applicable | none |
| universe-t1552-local-unknown | persistence | T1552.001 | web-server | unknown | preconditions |
| universe-t1566-attachment-unknown | initial_access | T1566.001 | web-server | unknown | trust_boundary |

## 解釈上の注意

母集団は、公開ATT&CKページで識別できるTechniqueを出発点にした評価用の脅威仮説です。
各候補の通信経路・境界・認証・認可・権限・前提条件は、対象システムへ照合するための明示的な評価プロファイルであり、ATT&CKページが特定環境の成立条件を保証するものではありません。
その解釈根拠は候補ごとの`source`と`applicability_profile.rationale`に保存しています。
候補を生成したこと自体は攻撃可能性を意味しません。条件が未確定の候補は`unknown`として残し、`blocked`だけを候補削減として集計します。

## expected_outcome 契約

- 判定: **passed**
- 不一致: `[]`
