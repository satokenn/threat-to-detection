# threat-to-detection

脆弱性情報と対象システムの脅威モデルを関連付け、SOCにおける検知設計を支援する小規模な試作システムです。

## 現在のスコープ

現時点では開発基盤を整えています。対象システムをYAMLから読み込み、型付きのドメインモデルとして扱い、後続のCollector・Mapper・Analyzerを追加できる構成にしています。

1週間の試作では、次の流れを1つのケースで通すことを目標にします。

```text
システム定義 → 脆弱性取得 → 関連付け → 攻撃候補 → 必要ログ → 検知ギャップ
```

CVEからATT&CKや具体的なログへの対応付けは一意に決まらない場合があるため、将来的な分析結果には根拠と信頼度を持たせます。本プロジェクトは、完全な自動検知ルール生成を目的としません。

## セットアップ

Python 3.10以上を使用します。uvがある場合は次のコマンドで開発環境を作成できます。

```bash
uv sync
uv run pytest
uv run threat-to-detection examples/web-system.yaml
uv run threat-to-detection fetch-cves --keyword "apache http server" --limit 10
```

uvを使わない場合は、仮想環境を作成したうえで開発用依存関係をインストールしてください。

```bash
python -m pip install -e ".[dev]"
pytest
python -m threat_to_detection.cli examples/web-system.yaml
python -m threat_to_detection.cli fetch-cves --cve-id CVE-2024-1234
```

## ディレクトリ構成

```text
src/threat_to_detection/
├── models/       # システム、脆弱性、脅威、検知のドメインモデル
├── collectors/   # NVD、KEVなど外部情報の取得
├── mappers/      # CVE/CWE/CAPEC/ATT&CK間の関連付け
├── knowledge/    # 検知挙動と必要ログの小さな知識ベース
├── analyzers/    # 関連性、攻撃経路、検知ギャップの分析
├── reporters/    # Markdown/JSONなどの出力
└── services/     # 処理全体のオーケストレーション
```

## 開発方針

- 外部APIの結果はfixtureで再現できるようにする
- 外部情報との関連付けには、可能な限り出典を保存する
- 「候補」と「確定した事実」をモデル上で区別する
- 実環境への配布やSIEM連携は今回の範囲外とする

## NVDからCVEを取得する

NVD API 2.0のCVEエンドポイントを利用しています。次のいずれか一つを指定して検索できます。

```bash
# CVE IDで取得
threat-to-detection fetch-cves --cve-id CVE-2024-1234

# CPEで取得
threat-to-detection fetch-cves \
  --cpe-name 'cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*'

# キーワードで取得
threat-to-detection fetch-cves --keyword "apache http server" --limit 20
```

検索結果は`data/cache/nvd/`に保存され、同じ検索は再利用されます。最新結果を取得したい場合は`--no-cache`を指定します。NVD APIキーを持っている場合は、環境変数に設定してください。

```bash
export NVD_API_KEY="your-api-key"
```

Collectorは取得結果をプロジェクト内の`Vulnerability`モデルへ正規化します。NVDのCPE applicability treeは現段階では最初の製品・バージョンを抽出しており、複雑なバージョン範囲の判定は今後の課題です。

システム定義のソフトウェアは`vendor`、`product`、`version`で記述します。`cpe`を明示した場合はそれを優先し、省略時はCPE 2.3を生成してNVD検索に使用します。

API仕様: [NVD Vulnerability API](https://nvd.nist.gov/developers/vulnerabilities)
