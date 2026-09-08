# 評価シナリオ

`scenario.yaml`は、リポジトリに同梱したNVD/CAPEC/ATT&CKの最小fixtureを使う再現可能な評価シナリオです。外部サービスには接続せず、実際の攻撃ペイロードも含めません。

```bash
PYTHONPATH=src python -m threat_to_detection.cli analyze evaluations/scenario.yaml \
  --nvd-fixture tests/fixtures/nvd/cves.json \
  --capec-fixture tests/fixtures/capec/attack_patterns.xml \
  --attack-fixture tests/fixtures/attack/enterprise-attack.json \
  --offline --output-dir evaluations/output
```

この実行で、`CVE-TEST-0001`（`example-product` 1.0）から次の経路を確認できます。

```text
CVE-TEST-0001 → CWE-79 → CAPEC-100 → T1059 → DET0001 → Sigma
```

同じCWEからCAPEC-101も候補になりますが、対応するATT&CK Techniqueがないため、`mapping_gaps`に記録されます。CAPEC-100からはT1105も得られますが、検知戦略がないため、ここでも経路が途切れます。これがこの評価で確認する多対多と欠落の例です。

サンプルJSONLは、生成されたルールの構造上の成立条件（EventID 1と`process.command_line`の存在）を確認するための安全な入力です。これは実攻撃の検知性能を示すものではありません。

評価結果の件数と考察は[`history.md`](history.md)、機械可読な記録は[`history.json`](history.json)、レビュー記録の雛形は[`review.md`](review.md)にあります。

`analysis.json`の`mode`と`snapshots`には、fixture / cache / online / refreshの取得モード、入力URL、release、固定識別子、取得日、raw SHA-256、正規化・除外条件が記録されます。`manifest.json`ではシナリオと各スナップショットから`analysis.json`およびSigma生成物への関係を確認できます。Apache HTTP Server 2.4.50の未対応経路は、fixtureへ推測の対応を追加せずcounterexampleとして履歴に残します。

## 実データの反例

Apache HTTP Server 2.4.50とCVE-2021-42013（CWE-22、CAPEC-126）は正規候補として調査しました。しかし現行ATT&CK EnterpriseスナップショットにはCAPEC-126からT1190への外部参照がないため、期待経路を推測で補わず、`CAPEC→ATT&CK`のcounterexampleとして扱います。
