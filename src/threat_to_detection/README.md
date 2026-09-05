# Pythonパッケージ

`threat_to_detection`の実装本体です。外部から利用する処理は、CLIまたは`services`を入口にします。

## 責務

- `models/`: 入力・中間結果・出力のドメインモデル
- `collectors/`: NVDなど外部情報源との通信と正規化
- `mappers/`: CVE、CWE、CAPEC、ATT&CKの関連付け
- `knowledge/`: 検知挙動と必要ログの対応表
- `analyzers/`: 関連性や検知ギャップの分析
- `reporters/`: 分析結果のMarkdown/JSON出力
- `services/`: 複数の処理をつなぐアプリケーションサービス

外部API呼び出しやファイルI/Oは、できるだけ`collectors`または`services`に閉じ込めます。モデルは外部サービスを直接呼び出しません。
