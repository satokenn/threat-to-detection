# Issue #26 evaluation fixture

このディレクトリは、Issue #23で選定した42件をIssue #26の公開マッピング評価へ
再入力するための固定スナップショットです。

- `capec-selected.xml`: 選定済みCVEに含まれる具体的なCWEに関連するCAPEC Attack Patternだけを収録
- `attack-selected.json`: 選定されたCAPEC候補に対するATT&CK外部参照がないことを表す空の関連範囲

CAPEC fixtureは、次の公開スナップショットから抽出しました。

- URL: `https://capec.mitre.org/data/xml/capec_latest.xml`
- source SHA-256: `70279a2dff0cb0ad79e546adb07828335a704ad5210e047e09e986172fc9e34d`
- 抽出条件: 選定42件の具体的CWE（27種類）と`Related_Weaknesses`が交差する215件
- fixture SHA-256: `94aa23978066259f66cbbd73926c2a65ac43e128825aebcb06bfd6ae1f81d534`

ATT&CK fixtureは、同じ公開スナップショットについて選定CAPEC候補を検索した結果、
該当する外部参照がなかったことを固定化しています。

- URL: `https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json`
- source SHA-256: `dc1639caa5501d720e280cf1cbd8fbe009884a0c9b3e6e9ed9d0c25166c3d8f4`
- fixture SHA-256: `f2e437774e89066bf843c145b1487cb3968b2f08393aa76d05754ef1cf392543`

外部スナップショットを再取得する場合は、`evaluate-cves --online`または明示的な
`--capec-path`／`--attack-path`を使います。固定評価の標準入力はこのfixtureです。
