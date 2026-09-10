# 評価履歴

## fixture-web-system-001

- シナリオ: [`scenario.yaml`](scenario.yaml)
- 実行モード: offline fixture
- 入力: NVD 1件、対象資産2件
- 到達件数: CWE 1、CAPEC候補2、ATT&CK Technique候補2、Detection Requirement 1、Sigma候補1
- 完全経路: 1
- ギャップ: 2（CAPEC-101 → ATT&CK、T1105 → Detection Requirement）
- サンプル: 安全なJSONL正例1件・負例1件を用意。実攻撃の再現や本番検知性能の評価ではない
- 出典: NVD / CAPEC / ATT&CKのURL、fixtureの固定識別子、raw SHA-256、正規化・除外条件を`analysis.json`と`manifest.json`で追跡
- サンプル判定: 正例 `1/1`、負例 `0/1`（いずれも期待結果どおり）
- 判定: `partial`。成功経路を保持しつつ、未解決の対応を明示できた

### 機械可読な差分

`history.json`の`diff.current`と`counterexamples`に、候補数・完全経路・ギャップ・Detection Requirement・Sigmaの比較値と、Apacheの未対応経路を記録する。ベースラインがない初回評価では`baseline: null`とし、未対応のATT&CK Techniqueを推測で追加しない。

### 考察

`CWE-79 → CAPEC-100/CAPEC-101`の多対多候補化により、候補数は増える。一方、CAPEC-101にはATT&CK対応がなく、CAPEC-100から得たT1105には検知戦略がないため、単純に「候補数 = 生成ルール数」にはならない。ATT&CKのDetection Strategy / Analyticは、観測するログやフィールドまでは与えるが、悪性値や攻撃固有の条件までは与えない。このため自動生成物は`detection_candidate`に留まり、人によるログ・正例・負例・誤検知レビューが必要である。

### 実データの反例

Apache HTTP Server 2.4.50 / CVE-2021-42013 / CWE-22 / CAPEC-126を確認した。現行ATT&CKスナップショットにはCAPEC-126の外部参照がないため、T1190を推測で付与せず、成功経路ではなくcounterexampleとして残す。これは公開知識ベース間の対応欠落を隠さないための記録である。

## cve-mapping-baseline-001

- 対象: Issue #23で選定した42件のCVE
- 実行: `evaluate-cves --offline`、対象システムの関連性とIssue #24の脅威モデル条件は未適用
- 到達件数: CWE 37、CAPEC 34、ATT&CK 0、Detection Requirement 0
- 最終到達段階: `cve=5`、`cwe=3`、`capec=34`、`attack=0`、`detection=0`
- mapping gap: 433（CVE→CWE 5、CWE→CAPEC 6、CAPEC→ATT&CK 422、ATT&CK→Detection Requirement 0）
- 主なボトルネック: 現行ATT&CKスナップショットで、選定されたCAPEC候補からATT&CK Techniqueへ到達できなかった
- 出力: [`cve-evaluation.json`](cve-evaluation.json)
- 出典ハッシュ: 固定fixtureのハッシュと元公開スナップショットのハッシュを`tests/fixtures/evaluation/README.md`、`cve-evaluation.json`、`history.json`に記録
- 判定: `partial`。公開情報の対応がない枝を推測で補わず、CVE単位の最遠到達段階と枝単位のgapを保存した

## evaluation-visualization-001

- 対象: 評価A [`cve-evaluation.json`](cve-evaluation.json) と評価B [`multidomain-results.json`](multidomain-results.json)
- 実行: `visualize-evaluations`、固定fixture由来の評価結果を入力、外部ネットワークなし
- 評価A集計: 母数42、CWE 37、CAPEC 34、ATT&CK 0、Detection Requirement 0
- 評価B集計: 事前候補6、適用6、blocked 0、unknown 0
- 出力: [`results/aggregates/`](results/aggregates/) と [`results/figures/`](results/figures/)
- 図: 累積到達率、段階間到達率、シナリオ別適用可否、blocked/unknown理由の4種類
- 判定: `pass`。集計値を固定入力から決定的に再生成でき、評価結果にないシナリオを0件として補完しない
