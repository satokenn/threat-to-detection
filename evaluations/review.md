# 評価レビュー

## Review

- review_id: fixture-web-system-001
- rule_id: `evaluations/output/analysis.json` の `assets.web-server.sigma_rules[0].rule_id` を記入
- reviewer: pending
- reviewed_at: pending
- decision: pending
- evidence: `CVE-TEST-0001 → CWE-79 → CAPEC-100 → T1059 → DET0001`
- logsource: `category: process_creation`
- positive_result: 未レビュー（安全な合成イベントを使用）
- negative_result: 未レビュー（安全な合成イベントを使用）
- false_positive_observations: 未評価
- constraints: ATT&CKのテレメトリ要件から生成した候補であり、悪性値は指定していない
- promotion_condition: 独立レビュアーが実ログで正例・負例・誤検知を確認する

このファイルを埋めるまで、生成ルールの`rule_kind`は`detection_candidate`から昇格させません。
