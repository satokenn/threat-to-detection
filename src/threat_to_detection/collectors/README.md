# collectors

外部の脆弱性・脅威情報源からデータを取得し、共通モデルへ正規化します。

現在は`nvd.py`がNVD CVE API 2.0に対応しています。APIキーは`NVD_API_KEY`から読み込み、レスポンスは`data/cache/nvd/`にキャッシュします。

通信を伴うテストは、HTTPレスポンスをfixtureまたは差し替え可能な openerで再現します。テストから実際のNVD APIを呼び出しません。
