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

# エンドツーエンド分析（既定はfixture/cacheのみ、output/analysis.jsonとoutput/sigma/*.ymlを出力）
uv run threat-to-detection analyze examples/web-system.yaml

# 不足データの取得を許可、またはキャッシュを強制更新
uv run threat-to-detection analyze examples/web-system.yaml --online
uv run threat-to-detection analyze examples/web-system.yaml --refresh

# 同梱fixtureを使ったネットワークなしの分析
uv run threat-to-detection analyze examples/web-system.yaml \
  --nvd-fixture tests/fixtures/nvd/cves.json \
  --capec-fixture tests/fixtures/capec/attack_patterns.xml \
  --attack-fixture tests/fixtures/attack/enterprise-attack.json \
  --offline --output-dir output

# Issue #23で選定したCVEを、公開マッピングの到達率として一括評価
uv run threat-to-detection evaluate-cves \
  --selection evaluations/cve-selection.json \
  --offline \
  --output evaluations/cve-evaluation.json
```

`analyze`は、一部の対応付けや外部レコードが欠落しても成功した経路を
失わないよう、部分的な分析では終了コード0を返します。`analysis.json`の
`status`と`errors`を確認してください。入力不正やレポート書き込み失敗は、
従来どおり非0のエラーになります。

`analysis.json`には、資産ごとのCVE / CWE / CAPEC / ATT&CK / Detection
Requirement、完全な経路、対応付けのギャップ、生成Sigmaの出典が含まれます。
Sigma候補には決定的な`id`と`detection_candidate`という`rule_kind`が付きます。
これはATT&CKのテレメトリ要件から作った候補であり、本番ルールや実攻撃の検知結果ではありません。
生成物の所有範囲とSHA-256は`manifest.json`に記録されます。

`evaluate-cves`は`evaluations/cve-selection.json`の42件を対象に、対象システムへの関連性を
適用せず、公開情報のCVE → CWE → CAPEC → ATT&CK → Detection Requirementの接続率を
`cve-evaluation.json`へ出力します。`records`にはCVEごとの最遠到達段階・候補数・mapping gapを、
`metrics`には累積到達率・段階間到達率・最終段階別件数・gapの段階別件数を保存します。
`NVD-CWE-noinfo`と`NVD-CWE-Other`は具体的なCWE到達として数えません。

14件の多分野シナリオは、固定fixtureを使って次のコマンドで再生成できます。

```bash
uv run threat-to-detection evaluate-scenarios \
  --capec-fixture tests/fixtures/capec/attack_patterns.xml \
  --attack-fixture tests/fixtures/attack/enterprise-attack.json \
  --nvd-fixture tests/fixtures/nvd/cves.json

# Issue #26 / #27の評価結果から、再現可能なSVG図と集計CSV/JSONを生成
uv run threat-to-detection visualize-evaluations \
  --evaluation-a evaluations/cve-evaluation.json \
  --evaluation-b evaluations/multidomain-results.json \
  --output-dir evaluations/results
```

`visualize-evaluations`は評価ロジックを再実行せず、保存済みの評価A/B JSONを入力として、
累積到達率、段階間到達率、脅威モデル適用後の`applicable / blocked / unknown`内訳、
`blocked / unknown`の理由別件数をそれぞれSVGで生成します。元の集計値は
`aggregates/evaluation_a_summary.csv`、`aggregates/evaluation_b_summary.csv`、
`aggregates/evaluation-summary.json`にも保存されます。数値は入力レコードから算出され、
`unknown`は候補削減率に含めません。

Issue #23の評価対象CVE 42件を再現可能に取得・選定する手順は
[`docs/cve-selection.md`](docs/cve-selection.md)にまとめています。既定の固定seedは`23`です。

```bash
uv run threat-to-detection select-cves --online \
  --output evaluations/cve-selection.json
```

## 再現可能な評価

同梱の評価シナリオは、外部APIへ接続せずにパイプライン全体を確認できます。

```bash
PYTHONPATH=src python -m threat_to_detection.cli analyze evaluations/scenario.yaml \
  --nvd-fixture tests/fixtures/nvd/cves.json \
  --capec-fixture tests/fixtures/capec/attack_patterns.xml \
  --attack-fixture tests/fixtures/attack/enterprise-attack.json \
  --offline --output-dir evaluations/output
```

評価では、`CVE-TEST-0001 → CWE-79 → CAPEC-100 → T1059 → DET0001 → Sigma`
の完全経路と、対応が途切れる2つのギャップを同時に確認できます。段階別の件数、
多対多対応の影響、検知要件からSigmaへ自動化できる範囲と人のレビューが必要な境界は
[`evaluations/README.md`](evaluations/README.md)と[`evaluations/history.md`](evaluations/history.md)
に記録しています。

## CI

Pull Requestと`main`への変更で、Python 3.10 / 3.14の静的チェック、構文チェック、テスト、固定fixtureによるネットワークなし評価を実行します。失敗時はGitHub Actionsの`quality`ジョブで、最初に失敗したステップとfixture出力の`analysis.json`を確認してください。

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

全体の責務、データフロー、外部情報源、対応付けの前提は[`docs/design.md`](docs/design.md)にまとめています。ドキュメントの入口は[`docs/README.md`](docs/README.md)です。

各ディレクトリの詳細は、それぞれのREADMEを参照してください。`examples/`は人が実行する入力例、`tests/`は機械的に正しさを検証するコードとfixtureです。両者は同じ目的ではありません。

- [`examples/README.md`](examples/README.md)
- [`tests/README.md`](tests/README.md)
- [`data/README.md`](data/README.md)

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
