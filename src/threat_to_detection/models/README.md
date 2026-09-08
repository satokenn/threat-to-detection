# models

処理で受け渡す共通ドメインモデルを置きます。

- `system.py`: 資産、ソフトウェア、通信経路、YAML入力
- `vulnerability.py`: CVE、CWE、CVSSなどの正規化結果
- `threat.py`: 攻撃候補と出典・信頼度
- `detection.py`: ATT&CKのDetection Strategy / Analytic、Data Component、検知要件、ログ不足
- `capec.py`: CAPEC Attack Pattern
- `attack.py`: MITRE ATT&CK TechniqueとTactic
- `sigma.py`: Sigma候補、出典、決定的ID、候補分類
- `provenance.py`: fixture / cache / online / refreshの取得モードとraw hash

ここではNVDやATT&CKのHTTP通信を行いません。入力が不正な場合は、後続処理に渡す前に検証します。
