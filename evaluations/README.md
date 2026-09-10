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

## 多分野シナリオ

脆弱性だけでは「データ分析」の比較が狭くなるため、入口の異なる10件を[`scenarios/index.yaml`](scenarios/index.yaml)に定義しています。

- vulnerability: CVEを入口にした2件（fixtureで検証できる例と、Apacheのcounterexample）
- malware: 安全な抽象挙動を入口にした3件
- identity: 認証・IDの挙動を入口にした2件
- network: 外部通信の挙動を入口にした1件
- cloud: 管理プレーンの挙動を入口にした1件
- control: 正常な管理操作を対照にした1件

各シナリオには、`scenario_type`、`entrypoint`、弱点または挙動から必要ログまでの分析チェーン、利用可能ログ、期待するgap、正例・負例JSONL、ベースラインと生成候補の比較欄があります。`required_logs`はイベント種別と必要フィールドを保持し、coverageはイベント・フィールド単位で計算します。人間向けの集計・考察は[`report.md`](report.md)です。

現行fixtureで裏付けられないTechniqueやDetection Strategyは、IDを推測せず`not_evaluated`または`counterexample`としています。カタログ全件のfixture実行状態はindexの`evaluation_status`と`multidomain-results.json`に記録します。実マルウェア、バイナリ、攻撃ペイロードは使用しません。

`analysis.json`の`mode`と`snapshots`には、fixture / cache / online / refreshの取得モード、入力URL、release、固定識別子、取得日、raw SHA-256、正規化・除外条件が記録されます。`manifest.json`ではシナリオと各スナップショットから`analysis.json`およびSigma生成物への関係を確認できます。Apache HTTP Server 2.4.50の未対応経路は、fixtureへ推測の対応を追加せずcounterexampleとして履歴に残します。

## 42 CVEの公開マッピング到達率

## 10シナリオの再生成

固定fixtureを指定すると、10シナリオの機械可読結果とレポートを同じ入力から再生成できます。

```bash
PYTHONPATH=src python -m threat_to_detection.cli evaluate-scenarios \
  --capec-fixture tests/fixtures/capec/attack_patterns.xml \
  --attack-fixture tests/fixtures/attack/enterprise-attack.json \
  --nvd-fixture tests/fixtures/nvd/cves.json \
  --output evaluations/multidomain-results.json \
  --report evaluations/report.md
```

Issue #23の選定結果を入力に、次のコマンドでIssue #26のベースラインを再生成できます。

```bash
PYTHONPATH=src python -m threat_to_detection.cli evaluate-cves \
  --selection evaluations/cve-selection.json \
  --offline \
  --output evaluations/cve-evaluation.json
```

この評価は対象システムへの関連性やIssue #24の脅威モデル条件を適用しません。`records`には
各CVEの到達可否、最遠到達段階、候補数、枝単位のgapを保存し、`metrics`には累積到達率と
段階間到達率を別々の分母で保存します。公開スナップショットに対応がない枝は推測で補完せず、
`mapping_gaps`に残します。

`evaluate-cves`の既定入力は[`tests/fixtures/evaluation/`](../tests/fixtures/evaluation/)の
固定スナップショットです。最新データで再評価する場合だけ`--online`を指定します。

## 実データの反例

Apache HTTP Server 2.4.50とCVE-2021-42013（CWE-22、CAPEC-126）は正規候補として調査しました。しかし現行ATT&CK EnterpriseスナップショットにはCAPEC-126からT1190への外部参照がないため、期待経路を推測で補わず、`CAPEC→ATT&CK`のcounterexampleとして扱います。
