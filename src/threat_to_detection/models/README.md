# models

処理で受け渡す共通ドメインモデルを置きます。

- `system.py`: 資産、ソフトウェア、通信経路、YAML入力
- `vulnerability.py`: CVE、CWE、CVSSなどの正規化結果
- `threat.py`: 攻撃候補と出典・信頼度
- `detection.py`: 検知候補と必要ログ、ログ不足

ここではNVDやATT&CKのHTTP通信を行いません。入力が不正な場合は、後続処理に渡す前に検証します。
