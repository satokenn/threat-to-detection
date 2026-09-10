# 検知分析・評価契約書

## 1. この文書の目的

この文書は、`threat-to-detection` の検知分析をどのような目的で行い、どの入力・出力・評価基準を守るかを定める。実装者、分析者、レビュー担当者が同じ前提で作業できるように、現在の位置付けと将来の到達点を分けて記録する。

この契約書の対象は、脅威知識の入口から攻撃経路と検知要件・必要ログを追跡し、検知候補を評価可能な形で出力するまでである。入口はCVEに限定せず、公開されたマルウェア挙動、認証・ID、ネットワーク、クラウドの挙動も扱う。実環境で攻撃を検知したことや、生成したSigmaをそのまま本番で使用できることを意味しない。

## 2. 合意した位置付け

### 2.1 現在の目的

現在は、再現可能なSOC研究・説明用のPoCである。固定した外部データと安全なサンプルを使って、次のことを説明できることを重視する。

- 対象システムに関係するCVEを特定する
- `CVE → CWE → CAPEC → ATT&CK → Detection Strategy / Analytic` の対応経路を追跡する
- 必要なテレメトリと、検知候補に使える根拠を整理する
- 対応付けが途切れた箇所や、人の判断が必要な箇所を隠さず示す
- 同じスナップショット、入力、コマンドから同じ評価結果を再現する
- CVE、マルウェア挙動、認証・ID、ネットワーク、クラウドという異なる入口を、共通の分析項目で比較する

### 2.2 将来の目的

将来は、本番級のルール生成へ段階的に近づける。ただし、本番配布、SIEM固有形式への変換、継続運用、自動承認は今回のスコープに含めない。内部実装の大きなリファクタリングも、まず実データによる評価が終わった後に行う。

### 2.3 Sigmaの位置付け

生成するSigmaは、テレメトリ要件を検証するための検知候補であり、本番ルールではない。曖昧な対応や不足データを、もっともらしいSigmaに変換して補ってはならない。候補を残す場合も、根拠、制約、未解決の曖昧さを出力する。

## 3. 成熟度と昇格条件

検知候補は、次の順番で成熟する。状態を飛ばして本番承認へ進めない。

```text
telemetry_validation → detection_candidate → reviewed_rule → production_approved
```

| 段階 | 意味 | 次の段階へ進むための条件 |
|---|---|---|
| `telemetry_validation` | 必要なログ、イベント、フィールドが取得・解釈できるかを確認する | テレメトリの存在と形式を確認する |
| `detection_candidate` | 対応経路と根拠を持つ検知候補を作る | シナリオ、正例・負例、マッピングの不足を確認する |
| `reviewed_rule` | 人が根拠と挙動をレビューした候補 | レビュー記録、適用ログソース、制約、FP観点を埋める |
| `production_approved` | 本番で運用する承認済みルール | 別レビュアーと運用責任者が承認し、ロールバック手順を持つ |

候補生成時の`rule_kind`は、入力された根拠と対応経路から保守的に自動分類する。人のレビュー前に`reviewed_rule`や`production_approved`と分類してはならない。`rule_kind`は`analysis.json`とSigmaのカスタムメタデータの両方に記録する。

## 4. 対象範囲と対象外

### 4.1 対象範囲

- NVD、CAPEC、MITRE ATT&CKの固定スナップショットを用いた分析
- 資産単位の脆弱性・攻撃経路・検知要件の追跡
- 複数候補、複数経路、曖昧な対応の保存
- Sigma候補の生成、内部検証、サンプルテレメトリによる評価
- 入口ごとに「弱点または挙動 → 悪用・攻撃者行動 → 監視対象 → 必要ログ → 利用可能ログとの差分」を分析する
- 複数シナリオを横断した分岐、経路脱落、ログ充足率、ベースラインと生成候補の比較
- JSON、YAML、JSONL、Markdownによる機械可読・人間可読な記録
- 評価A/Bの集計CSV/JSONと、到達率・候補適用可否・理由の静的SVG可視化

### 4.2 対象外

- すべてのCVEに対する完全自動の攻撃可能性判定
- ATT&CKから本番用検知ルールへの完全自動変換
- Sigmaルールの自動配布やSIEM / EDRとの本格連携
- 実環境の資産・ログの自動収集
- 実マルウェア、バイナリ、攻撃ペイロードの収集・実行・再現
- AIによる最終的な攻撃・検知判断
- 継続監視、定期更新、Web UI、SIEM固有の最適化

出力上の表現もこの境界を守る。「攻撃を検知した」ではなく、「候補経路」または「必要なテレメトリ要件」と表現する。

## 5. 分析経路と候補の扱い

基本経路は次のとおりである。

```text
対象資産
  → CPE / 製品バージョン
  → CVE / CWE
  → CAPEC
  → ATT&CK Technique（サブテクニックを含め、IDを改変しない）
  → Detection Strategy / Analytic
  → Data Component / イベント / フィールド
  → Sigma検知候補
```

各段階で次の境界を個別に評価し、`mapping_gaps`へ保存する。

- CVE → CWE
- CWE → CAPEC
- CAPEC → ATT&CK
- ATT&CK Technique → Detection Requirement

対応は一意とは限らないため、候補集合と全経路を保持する。複数のログソースが必要な場合は、1つの不正確なSigmaへ平坦化せず、戦略・根拠ごとに別候補として生成する。共有されるDetection Strategyも、各Techniqueからの根拠を失わない。

対応付けの根拠がデータソースに明示されている場合だけ信頼度を記録し、明示されていない場合は`unknown`とする。根拠のない推測で信頼度を補ってはならない。

検知候補として採用する最低条件は、NVD由来のCWE、追跡可能な対応経路、固定された製品バージョンがそろっていることである。これらを満たさない候補は、候補数を水増しせず、ギャップまたはcounterexampleとして記録する。

### 5.1 信頼境界・認証・権限条件

攻撃経路の「到達できる」と「必要な認証・権限を満たしている」は別の事実として扱う。`Asset.trust_zone` / `privilege_level`、`Flow.trust_boundary`、`Flow.authentication`、`Flow.authorization`を入力として保持し、分析JSONの`threat_analysis`にも出力する。シナリオには、必要に応じて`required_privilege`、`privilege_transition`、`required_authentication_logs`を明示できる。

未指定の値は`unknown`として扱う。プロトコル名、信頼ゾーン名、フローの存在だけから認証・認可・権限を推測してはならない。視覚的なDFD全体境界は、対象システム内の`trust_boundary`とは異なる。DFDの仕様とHTMLは、この区別と入力フィールドを表示する。

## 6. 正規評価シナリオ

### 6.0 多分野シナリオ群

評価対象は、日付ごとにディレクトリを増やすのではなく、[`evaluations/scenarios/index.yaml`](../evaluations/scenarios/index.yaml)と同じ階層のシナリオファイルで管理する。現在の設計対象は次の14件である。

| 分野 | 件数 | 入口 | 状態 |
|---|---:|---|---|
| vulnerability | 2 | CVE | fixture-backedの例、Apacheのcounterexample |
| malware | 7 | 公開された抽象挙動 | 一部fixture-backed、脅威モデル条件fixtureを含む |
| identity | 2 | 認証・IDの抽象挙動 | 未評価 |
| network | 1 | 外部通信の抽象挙動 | 未評価 |
| cloud | 1 | 管理プレーンの抽象挙動 | 未評価 |
| control | 1 | 正常な管理操作 | 対照、未評価 |

各シナリオは、CVEを持たない場合でも、`scenario_type`と`entrypoint`を明示し、弱点または挙動、悪用・攻撃者行動、監視、必要ログ、利用可能ログ、期待するgap、正例・負例、比較条件を記録する。現行fixtureにないTechniqueやDetection Strategyを推測で追加してはならない。評価結果の集計と考察は[`evaluations/report.md`](../evaluations/report.md)に記録する。

### 6.1 Canonical候補

実データによる正規評価の第一候補は、Apache HTTP Serverの次の組み合わせとする。

```text
CVE:     CVE-2021-42013
Version: 2.4.50（文字列として固定）
期待経路: CVE-2021-42013 → CWE-22 → CAPEC-126 → T1190 → DET0080
```

この経路はfixtureへ手作業で追加して成立させない。固定スナップショットに実際に存在する対応を検証して成立させる。期待経路がスナップショットにない場合は、その評価を正規候補として扱わず、失敗した評価をcounterexampleとして保存し、別の候補へ切り替える。

### 6.2 入力ファイル

`scenario.yaml`は、資産ごとに必要な情報を持つ。特に`logsource`は全体で一つに暗黙決定せず、各assetに明示する。

```yaml
system:
  metadata:
    name: apache-canonical
  assets:
    - name: web-server
      type: server
      software:
        - vendor: apache
          product: http_server
          version: "2.4.50"
      logsource:
        category: webserver
        service: apache
```

ログソースが複数ある場合は、それぞれを別の検知候補として評価し、候補間の関係を分析結果に残す。

### 6.3 サンプルテレメトリ

テレメトリは汎用JSONLで保持し、1行1イベントとする。最低限、次のフィールドを持つ。

```json
{"timestamp":"2026-01-01T00:00:00Z","event_id":"http.request","source":"apache","message":"safe synthetic request"}
```

匿名化した正例・負例を用意し、実際の悪用ペイロードは含めない。HTTP、エラー、プロセス、ネットワークなどの抽象的で安全な値を使う。評価結果は「攻撃成功」ではなく、候補が要求するテレメトリをサンプルが満たしたかとして記録する。

## 7. 外部データ、固定、再現性

### 7.1 取得モード

通常実行はfixtureまたはローカルキャッシュを使う。CIも外部APIへ接続しない。

- 既定: fixture / cache優先、オフラインで再現可能
- `--online`: 不足データを外部から取得してよい
- `--refresh`: キャッシュを強制更新する。`--online`も有効にする

最新データを使う行為は明示的に指定する。通常実行が無自覚にネットワークへ接続してはならない。

### 7.2 スナップショットの記録

各入力データについて、可能な限り次を記録する。

- 取得元URL
- リリースまたはデータバージョン
- 取得日
- リリースのSHAまたは同等の固定識別子
- rawデータのハッシュ
- 正規化条件、除外条件、取得モード

NVDは正規化済みモデルを分析に使い、rawレスポンスのハッシュと正規化条件を記録する。巨大なrawスナップショットをGitへ追加しない。必要な最小fixtureは`tests/fixtures/`へ置き、再生成可能なキャッシュは`data/cache/`で管理する。

## 8. CLI契約と終了コード

標準的な実行は次の形とする。

```text
threat-to-detection analyze scenario.yaml [オプション]
```

主な契約は次のとおりである。

- `--online`: 外部データの取得を許可する
- `--refresh`: キャッシュを更新する（`--online`を伴う）
- `--strict`: 部分成功を厳格に扱う
- `--output-dir`: 出力先を指定する。通常の最新結果は`output/`に置く
- 資産ごとの`logsource`を読み取り、必要に応じてCLI指定で明示的に上書きする
- `--verbose`: マッピングや評価の詳細を表示する

既存利用者向けの`run_pipeline`呼び出しは互換性ラッパーとして維持する。新しいCLIや出力契約を追加しても、既存の基本的なパイプライン利用を理由なく破壊しない。

終了コードは次のとおりとする。

| コード | 意味 |
|---:|---|
| `0` | 完全成功、または通常モードでの部分成功。対応なし（no-match）もエラーではない |
| `3` | `--strict`指定時の部分成功。完全な経路がない、または未解決のギャップがある |
| `2` | 入力不正、データ取得失敗、解析不能などの致命的失敗 |

完全な経路が0件でも、入力が正常で分析が実行できた場合はno-match successとして扱う。no-matchをmapping failureや取得失敗に偽装しない。

## 9. 出力契約

### 9.1 最新出力

通常の最新結果は、日付ごとの大量のディレクトリを作らず、次のように固定した場所へ置く。

```text
output/
├── analysis.json
├── manifest.json
└── sigma/
    └── <deterministic-name>.yml
```

`analysis.json`の最上位には、互換性確認のため次を含める。

- `schema_version: "1.0"`
- 実行日時、シナリオ識別子、取得モード
- 資産ごとの分析結果と全経路
- `mapping_gaps`
- `warnings`
- `errors`
- 全体ステータス（`success` / `partial` / `failed`）
- Sigma候補と`rule_kind`
- 各候補経路の決定的な`path_id`（シナリオ、資産、経路上の識別子から生成）
- 出典、スナップショット、ハッシュ、評価メトリクス

`mapping_gaps`、`warnings`、`errors`は意味が異なるため、別の配列として出力する。完全経路とギャップが同時に存在する結果は`partial`とする。

### 9.2 manifest

`output/manifest.json`は、その実行が生成・所有するファイルだけを列挙する。各ファイルの相対パス、種類、ハッシュ、生成状態、入力・スナップショットとの関係を記録する。生成状態には少なくとも次を区別する。

```text
generated / written / write_failed / generation_failed
```

manifestにない利用者ファイルは削除・上書きしない。再実行時は、manifestが所有する範囲だけを安全に置き換える。

### 9.3 履歴

評価の変遷は、日付ごとの巨大な出力コピーではなく、読みやすい履歴として残す。

- `evaluations/history.md`: 人が読む要約、判断、差分、counterexample、制約
- `evaluations/history.json`: 実行ごとの機械可読な比較情報

履歴には、入力・スナップショット・コード変更による差分として、候補数、完全経路数、ギャップ数、Technique数、Detection Requirement数、Sigma数、根拠の変更を記録する。URL、リリース・バージョン、取得日、SHA、raw hashも機械可読結果だけでなく、人間向けの履歴から追跡できるようにする。最新の機械可読成果物は`output/`に置き、履歴には出典とファイルへの参照を持たせる。

### 9.4 評価結果の可視化

評価A/BのJSONは、評価ロジックを再実行せずに集計・可視化できる入力成果物とする。`visualize-evaluations`は、評価Aの累積・段階間到達率と、評価Bのシナリオ別の`applicable`・`blocked`・`unknown`および理由を、集計CSV/JSONと静的SVGとして出力する。

- 既定の評価Bシナリオが入力に存在しない場合、0件として補完せず入力エラーにする
- `unknown`は`blocked`や候補削減数へ合算しない
- 評価結果に含まれる件数と図の値は同じ集計結果から生成する
- SVGはヘッドレスCIで生成できる静的成果物とし、外部ネットワークや固定値に依存しない

## 10. Sigma候補の契約

Sigmaは内部バリデータで必須フィールドと型を検証する。外部のpySigmaなどのバリデータは開発環境で使ってよいが、CIや通常の完了条件には必須としない。

生成ルールは次を守る。

- `title`、`logsource`、`detection`を必須とする
- 既定の`status`は`experimental`
- 既定の`level`は`low`
- `rule_kind`をカスタムメタデータとして含める
- Sigma IDは、scenario、asset、Technique、strategy、logsourceから決定的に生成する（UUIDv5相当）。同じ入力から同じIDを得る
- ATT&CK Techniqueタグは元のIDを保持する
- 根拠が明示できないイベントIDやフィールドを推測しない
- 複数イベントIDは必要に応じてscalarまたはlistとして表現する
- 明示的に存在を確認できる場合に限り`exists`を使う
- 曖昧なイベントはSigma条件へ無理に入れず、provenanceと警告へ残す

候補の`rule_kind`は、対応経路の完全性、テレメトリの明示性、曖昧さ、レビュー状態を用いて保守的に決定する。候補を本番ルールと誤認させる分類は禁止する。

## 11. マッピングギャップ、警告、制約

失敗を一つの空結果に隠さず、原因ごとに記録する。

- `mapping_gaps`: 対応先が存在しない、または条件が不足している
- `warnings`: 処理は継続できるが、判断に注意が必要
- `errors`: 入力不正、取得失敗、壊れたbundleなど処理を成立させられない

不正な個別オブジェクトは、可能ならスキップしてwarningとする。不正なbundle全体など解析不能な入力はfatal errorとする。CPE・製品・バージョン照合がない場合はgapとして扱い、脆弱性を作り出さない。対象パスがない場合も、no-matchまたはpartialとして原因を残す。

## 12. 評価・レビュー記録

正規シナリオでは、最低限次のメトリクスを比較する。

- 入力資産数と対象CVE数
- 完全経路数、候補経路数、マッピングギャップ数
- Technique数、Detection Requirement数、Sigma候補数
- 正例・負例の件数と結果
- `rule_kind`、出典、根拠、制約の有無

`review.md`には、候補ごとに次のテンプレートを使う。

### `review.md`のテンプレート

```markdown
## Review

- review_id:
- rule_id:
- reviewer:
- reviewed_at:
- decision: pending | accept | reject | revise
- evidence:
- logsource:
- positive_result:
- negative_result:
- false_positive_observations:
- constraints:
- promotion_condition:
```

`production_approved`には、作成者とは別のレビュアー、運用責任者、ロールバック手順が必要である。

## 13. テストとCI

CIは固定fixtureだけで実行し、外部APIや最新データに依存しない。最低限、サポート対象Pythonの最小バージョンと最新安定版で次を検証する。

- 単体テスト、入力スキーマ、正規化、対応付け
- canonicalシナリオのEnd-to-End経路と、期待するCVE/CWE/CAPEC/ATT&CK/Detection Strategy
- 0件、1件、複数件、共有戦略、サブテクニック、曖昧さ
- `mapping_gaps` / `warnings` / `errors`の分離
- `success` / `partial` / `failed`、no-match、`--strict`の終了コード
- `analysis.json`の`schema_version`と`rule_kind`
- Sigmaの必須フィールド、決定的ID、YAML出力、パスとmanifest
- 評価A/B可視化の集計値、4種類のSVG、空入力、欠落・重複シナリオのエラー
- 正例・負例のJSONL評価
- snapshotのURL、release、日付、SHA、raw hash

利用者受け入れでは、fixtureを使ったCLI実行、JSON/YAMLの内容確認、ギャップ表示、`rule_kind`、canonical結果、評価A/B可視化、READMEとの手順整合を確認する。

実データを更新する処理やオンライン通信は、CIとは別の明示的な手動・定期処理として扱う。

## 14. 完了条件

この契約に基づく評価を完了したとみなすには、次を満たす。

1. `scenario.yaml`、固定snapshotのmanifest、正例・負例JSONLがある
2. fixture/cache優先のCLI実行で`analysis.json`とSigma候補を生成できる
3. `output/manifest.json`が生成物を所有し、再実行で利用者ファイルを壊さない
4. `schema_version: "1.0"`、自動`rule_kind`、決定的Sigma IDが出力される
5. canonical経路を検証し、存在しなければcounterexampleとして保存する
6. マッピングギャップ、warning、error、制約が追跡可能である
7. `evaluations/history.md`と`history.json`で結果の変遷を比較できる
8. `review.md`にレビュー情報を記録できる
9. 単体・統合・CLI・スキーマ・Sigma・パス・ギャップのテストがCIで通る
10. READMEの利用手順とこの契約書の内容が一致し、利用者が結果を「本番検知」と誤解しない

コミット、Pull Request、CIのmerge可能性確認は、上記の実装・評価・ユーザー受け入れが完了してから別途行う。今回の設計合意だけでは、外部公開や本番承認を行わない。

## 15. 変更時の原則

CLI、`analysis.json`の主要構造、出力ファイルの意味は安定した契約として扱う。Python内部のクラスやディレクトリは、互換性を壊さない範囲でリファクタリングしてよい。

仕様を変更するときは、次を同時に更新する。

1. この契約書
2. `docs/design.md`または該当パッケージREADME
3. fixtureと実行例
4. スキーマ・単体・End-to-Endテスト
5. `evaluations/history.md`と`history.json`の変更記録

データ不足を黙って補完する変更、根拠を失わせる短縮、固定性を壊す暗黙のネットワーク取得は受け入れない。

曖昧な仕様や未合意の将来要件は、実装者の判断で追加せず、必要な範囲を明示して合意を取り直す。変更時も、既存のCLI互換性とユーザー所有の作業ツリー変更を保持する。コミット、Push、Pull Request、外部サービスへの更新などの外部アクションは、実装・評価とは分けて、別途承認を得てから行う。
