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

各シナリオには、`scenario_type`、`entrypoint`、弱点または挙動から必要ログまでの分析チェーン、利用可能ログ、期待するgap、正例・負例JSONL、ベースラインと生成候補の比較欄があります。`required_logs`はイベント種別と必要フィールドを保持し、coverageはイベント・フィールド単位で計算します。`expected_outcome`を宣言したfixtureは、評価時に実測結果と照合します。人間向けの集計・考察は[`report.md`](report.md)です。

ATT&CK候補ごとの適用可否・検知可能性の判定順序と出力契約は[`../docs/applicability-algorithm.md`](../docs/applicability-algorithm.md)に記載しています。`candidate_evaluations`には`trace_id`、`technique_id`、`evaluated_conditions`、`evidence`、`provenance`を保存します。

現行fixtureで裏付けられないTechniqueやDetection Strategyは、IDを推測せず`not_evaluated`または`counterexample`としています。判定機構の境界条件を確認する4件は、実脅威カタログとは分離した[`scenarios/condition-fixtures.yaml`](scenarios/condition-fixtures.yaml)で評価します。実マルウェア、バイナリ、攻撃ペイロードは使用しません。

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

## 脅威候補母集団の選別

`threat-universe.yaml`には、公開ATT&CKページを参照する18件の脅威仮説を登録しています。固定seed 41で
domainごとに2件ずつ、計12件を抽出します。各候補には対象asset、flow方向・プロトコル、信頼境界、認証・認可、
権限、前提条件を個別に記録するため、「候補経路が生成された」ことと「対象システムに適用可能」なことを分離できます。

```bash
PYTHONPATH=src python -m threat_to_detection.cli evaluate-threat-universe \
  --universe threat-universe.yaml \
  --output threat-universe-results.json \
  --report threat-universe-report.md
```

固定seedの結果は、applicable 5、blocked 3、unknown 4、候補削減率0.250です。これは公開Technique IDと
対象システム照合用の評価プロファイルによる安全なfixture評価であり、実環境での攻撃成功率や検知性能ではありません。

## 評価A/Bの可視化

評価A（CVEマッピング）と評価B（脅威モデル条件）の結果から、集計CSV/JSONと4種類の静的SVGを再生成できます。

```bash
PYTHONPATH=src python -m threat_to_detection.cli visualize-evaluations \
  --evaluation-a evaluations/cve-evaluation.json \
  --evaluation-b evaluations/multidomain-results.json \
  --output-dir evaluations/results
```

出力先には、`aggregates/evaluation-summary.json`、評価A/Bの集計CSV、次の図が生成されます。

```text
evaluations/results/
├── aggregates/
│   ├── evaluation-summary.json
│   ├── evaluation_a_summary.csv
│   └── evaluation_b_summary.csv
└── figures/
    ├── cumulative_reachability.svg
    ├── stage_reachability.svg
    ├── threat_model_applicability.svg
    └── applicability_reasons.svg
```

評価Bは`candidate_evaluations`の判定を集計し、`unknown`を`blocked`や候補削減数へ合算しません。既定の4候補生成シナリオが入力に存在しない場合は、0件として黙って補完せずエラーにします。入力が明示的に空の場合だけ、空の集計を生成します。脅威モデルの境界fixtureは、評価Bの母集団へ混ぜず、`condition-fixtures.yaml`でexpected_outcomeを実行検証します。

## 実データの反例

Apache HTTP Server 2.4.50とCVE-2021-42013（CWE-22、CAPEC-126）は正規候補として調査しました。しかし現行ATT&CK EnterpriseスナップショットにはCAPEC-126からT1190への外部参照がないため、期待経路を推測で補わず、`CAPEC→ATT&CK`のcounterexampleとして扱います。
