# 評価履歴

## fixture-web-system-001

- シナリオ: [`scenario.yaml`](scenario.yaml)
- 実行モード: offline fixture
- 入力: NVD 1件、対象資産2件
- 到達件数: CWE 1、CAPEC候補2、ATT&CK Technique候補2、Detection Requirement 1、Sigma候補1
- 完全経路: 1
- ギャップ: 2（CAPEC-101 → ATT&CK、T1105 → Detection Requirement）
- サンプル: 安全なJSONL正例1件・負例1件を用意。実攻撃の再現や本番検知性能の評価ではない
- 判定: `partial`。成功経路を保持しつつ、未解決の対応を明示できた

### 考察

`CWE-79 → CAPEC-100/CAPEC-101`の多対多候補化により、候補数は増える。一方、CAPEC-101にはATT&CK対応がなく、CAPEC-100から得たT1105には検知戦略がないため、単純に「候補数 = 生成ルール数」にはならない。ATT&CKのDetection Strategy / Analyticは、観測するログやフィールドまでは与えるが、悪性値や攻撃固有の条件までは与えない。このため自動生成物は`detection_candidate`に留まり、人によるログ・正例・負例・誤検知レビューが必要である。

### 実データの反例

Apache HTTP Server 2.4.50 / CVE-2021-42013 / CWE-22 / CAPEC-126を確認した。現行ATT&CKスナップショットにはCAPEC-126の外部参照がないため、T1190を推測で付与せず、成功経路ではなくcounterexampleとして残す。これは公開知識ベース間の対応欠落を隠さないための記録である。
