# mappers

脆弱性・攻撃情報の分類体系間の関連付けを置きます。

想定する流れは`CVE → CWE → CAPEC → ATT&CK`です。ただし、これらの対応は常に一意とは限らないため、候補・出典・信頼度を保持します。

現在の`cwe_to_capec.py`はCAPECの`Related_Weaknesses`を使って逆引き索引を作り、1つのCWEに対して0件、1件、複数件の候補を返します。

`capec_to_attack.py`はATT&CK STIXの外部参照を使って、CAPEC IDからTechniqueを逆引きします。ATT&CK側に対応がないCAPECは空の候補として扱います。
