# collectors

外部の脆弱性・脅威情報源からデータを取得し、共通モデルへ正規化します。

現在は`nvd.py`がNVD CVE API 2.0に、`capec.py`がCAPEC公式XMLのダウンロード・解析に対応しています。NVDのAPIキーは`NVD_API_KEY`から読み込み、レスポンスは`data/cache/nvd/`にキャッシュします。CAPEC XMLは取得先を指定してローカルへ保存できます。

`attack.py`はMITRE ATT&CK EnterpriseのSTIX JSONをダウンロード・解析します。Attack PatternのCAPEC外部参照とTacticを抽出します。

通信を伴うテストは、HTTPレスポンスをfixtureまたは差し替え可能な openerで再現します。テストから実際のNVD APIを呼び出しません。

CAPECの配布データは公式ダウンロードページから取得します。取得したXMLの全量をGitへ含めず、テストでは`tests/fixtures/capec/`の最小XMLを使います。

公式配布ページ: https://capec.mitre.org/data/downloads
