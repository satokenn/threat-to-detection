# NVD fixture

`cves.json`は、NVD CVE API 2.0のレスポンスを再現する最小fixtureです。

実際のAPIを呼び出さずに、CVE ID、説明、CWE、CVSS、CPEの正規化処理を検証するために使います。API仕様の変更を反映する場合は、対応するテストも同時に更新します。
