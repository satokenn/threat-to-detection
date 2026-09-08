# reporters

分析結果を人が読む形式や機械処理可能な形式へ変換します。

- Markdown: 課題レポートやレビュー向け
- JSON: 後続処理やテスト向け
- Sigma YAML: ATT&CKの検知要件から生成する保守的な検知候補

reporterは分析を行わず、受け取ったモデルを表示用に変換します。Sigma出力は
`title`、`logsource`、`detection`、ATT&CKタグ、出典メタデータを検証してから出力します。
