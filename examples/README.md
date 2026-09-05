# examples

人が読み、CLIで実行する入力例を置きます。ここにあるファイルは、システムモデルの書き方を理解するためのサンプルです。

## 実行

```bash
threat-to-detection examples/web-system.yaml
```

## YAMLの役割

`system.assets`に資産とソフトウェア、`system.flows`に通信経路を記述します。ソフトウェアは`vendor`、`product`、`version`を必須の基本情報とし、必要なら`cpe`を明示できます。

サンプルには実環境の秘密情報や本番資産情報を入れません。テストの正解データは`tests/fixtures/`に置き、examplesと混ぜません。
