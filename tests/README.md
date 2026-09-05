# tests

実装が期待どおり動くことをpytestで自動検証します。`examples/`が利用者向けの入力例であるのに対し、`tests/`は開発者向けの検証コードです。

## 実行

```bash
pytest
```

## 分類

- `test_system.py`: YAML、Pydanticモデル、CPE生成
- `test_nvd.py`: NVDレスポンスの正規化、キャッシュ、APIキー、CPE検索
- `test_pipeline.py`: 資産と脆弱性の関連付け
- `test_detection.py`: 必要ログと不足ログの判定
- `fixtures/`: 外部APIレスポンスなど、テストで再利用する固定データ

テストはネットワークやNVD APIキーに依存しません。新しい外部レスポンスを追加する場合は、まずfixtureとして保存し、テスト内に大きなJSONを直接埋め込まないようにします。
