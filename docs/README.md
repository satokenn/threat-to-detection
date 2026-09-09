# ドキュメント

このディレクトリには、実装の責務やデータの流れを説明する設計ドキュメントを置きます。

## ドキュメント一覧

- [`design.md`](design.md): システム全体の目的、構成、データフロー、責務、制約
- [`agreement.md`](agreement.md): 検知分析・評価の目的、入力・出力・CLI・Sigma・評価・完了条件の合意
- [`cve-selection.md`](cve-selection.md): Issue #23のCVE候補抽出、カテゴリ分類、固定seed選定
- [`../evaluations/scenarios/index.yaml`](../evaluations/scenarios/index.yaml): 分野別10シナリオの評価対象と状態
- [`../evaluations/report.md`](../evaluations/report.md): 分岐、脱落、ログ充足率、比較評価を記録するレポート雛形
- [`overall-architecture.html`](overall-architecture.html): 初見の読者向けの全体像アーキテクチャ
- [`overall-architecture.architecture.json`](overall-architecture.architecture.json): アーキテクチャ図のArchify仕様

実装の細部は各パッケージのREADMEを参照してください。設計書には「現在実装されている内容」と「今後の拡張案」を分けて記載します。
