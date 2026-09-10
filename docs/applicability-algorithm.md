# ATT&CK経路の適用可否・検知可能性判定仕様

## 1. 用語・状態定義

評価対象は、公開情報またはシナリオのATT&CK候補を表す`TracePath`、または公開Techniqueを
母集団から抽出した`ThreatUniverseCandidate`です。
`before_candidate`は脅威モデルを適用する前の候補であることを示し、候補を削除せずに判定結果を付与します。

攻撃適用可否（`attack_applicability`）は、対象環境で攻撃経路が成立し得るかを表します。

- `applicable`: 少なくとも1つの候補Flowについて必要条件がすべて明示的に成立
- `blocked`: 候補Flowがなく、またはすべての候補Flowに明示的な不成立条件がある
- `unknown`: blockedはないが、成立・不成立を確定できない条件がある

検知可能性（`detection_feasibility`）は、成立性とは独立したテレメトリ評価です。
`detectable`、`partial`、`unavailable`、`unknown`の4値を持ちます。ログ不足は攻撃経路をblockedにしません。

## 2. 入力フィールドと出典の優先順位

判定は、入力に明示された値だけを使います。プロトコル、ゾーン名、Flowの存在だけから認証・認可・権限を補完しません。

| 判定 | 入力 | 出典 |
|---|---|---|
| 到達性 | `Flow.from` / `Flow.to` | `system_model` |
| 信頼境界 | `Flow.trust_boundary` / `ScenarioContext.required_trust_boundary` | `system_model` / `scenario_author` |
| 認証 | `Flow.authentication` | `system_model` |
| 認可 | `Flow.authorization` | `system_model` |
| 権限 | `Asset.privilege_level` / `ScenarioContext.required_privilege` | `system_model` / `scenario_author` |
| 権限遷移 | `ScenarioContext.privilege_transition` | `scenario_author` |
| 候補固有条件 | `ThreatApplicabilityProfile`のflow方向・送信元・プロトコル・前提条件 | `scenario_author` / `public_threat_intel` |
| 検知 | `DetectionRequirement`、`required_logs`、`Asset.logs`、`available_log_fields` | `public_threat_intel` / `scenario_author` / `system_model` |

`satisfied: false`は明示的な不成立、`satisfied: true`は明示的な成立です。`required: false`はその条件が不要であることを表します。

## 3. `attack_applicability` の判定順序

1. 候補固有の`flow_scope`、方向、送信元、プロトコルで候補Flowを絞る。ネットワークFlowがなければ`reachability=blocked`。`local`候補はネットワークFlowを要求しない。
2. `trust_boundary_required: false`なら境界の宣言を要求せず、`true`なら`required_trust_boundary`との一致を確認する。必要なのに未指定なら`unknown`。
3. 認証・認可を候補固有の`*_required`とFlowの明示値で評価する。候補が要求しない場合だけ`false`を根拠に`satisfied`とする。
4. 候補固有の`privilege_required`が`true`なら`required_privilege`と対象Assetの権限を比較し、`false`なら権限を要求しない。未指定は`unknown`。
5. `required_preconditions`がある場合、対象SystemModelの`preconditions`にすべて明示されているかを確認する。未宣言は`unknown`とし、既存足場などを推測しない。
6. 既存TracePathでは、上記の候補固有条件の代わりに`ScenarioContext`の条件を使う。`privilege_transition`が指定された場合は送信元・対象Assetの権限を比較する。

Flowごとの条件を次の表で集約します。

| Flowの状態 | TracePathの状態 |
|---|---|
| 1つ以上が全条件`satisfied` | `applicable` |
| 全Flowが`blocked` | `blocked` |
| blockedはなく、unknownがある | `unknown` |

複数Flowは`flow_evaluations`に個別保存します。代替Flowのうち1つがapplicableなら、TracePathはapplicableです。

## 4. `detection_feasibility` の判定順序

必要イベント、必要フィールド、認証ログ、Assetのログ宣言を個別評価します。

| 条件 | `available` | `missing` | `unknown` |
|---|---|---|---|
| required telemetry | 必要イベントがAssetまたはシナリオにある | 必要イベントがない | 必要イベント自体が未指定 |
| required fields | 全フィールドがある | 一部または全部がない | 必要フィールドが未指定 |
| authentication logs | 必要認証ログがある | 必要認証ログがない | 必要性または取得状況が未指定 |
| asset logs | `Asset.logs`が宣言されている | - | ログ取得状況が未指定 |

全条件がavailableなら`detectable`、一部不足なら`partial`、必要イベントまたはフィールドが利用不能なら`unavailable`、取得状況を判断できなければ`unknown`です。

## 5. 複数Flow・複数TracePath

各TracePathは独立して評価し、別のTracePathのFlowやログを混ぜません。候補の検知戦略がない場合も候補Pathを保持し、検知可能性を`unknown`として記録します。
全体の`before_candidate_count`、3状態の件数、理由別件数は個別レコードから再計算できます。

## 6. `blocked` と `unknown` の具体例

```yaml
# blocked: Flowが存在しない
assets: [{name: server, privilege_level: user}]
flows: []

# unknown: Flowはあるが境界・認証・認可・必要権限が未指定
flows: [{from: internet, to: server, protocol: https}]

# blocked: 権限不足
scenario:
  required_privilege: admin
assets: [{name: server, privilege_level: user}]
```

`https`は暗号化方式を示すだけで、認証済みとは解釈しません。

## 7. 攻撃は成立するが検知不能な例

Inbound Flow、境界、認証・認可、対象権限が明示的に成立していても、`Asset.logs`に必要なProcess Creationイベントがなければ、結果は
`attack_applicability=applicable`かつ`detection_feasibility=unavailable`です。

## 8. provenance / evidence schema

各判定オブジェクトは次の形を持ちます。

```json
{
  "status": "applicable",
  "reasons": ["All required attack applicability conditions are satisfied."],
  "evidence": [{"kind": "flow", "id": "internet->server", "field": "trust_boundary", "value": "internet-to-dmz"}],
  "evaluated_conditions": [{"condition": "reachability", "status": "satisfied", "reason": "..."}],
  "provenance": [{
    "source_type": "system_model",
    "source_id": "flow:internet->server",
    "field": "trust_boundary",
    "rationale": "The value is explicitly declared in the SystemModel."
  }]
}
```

`source_type`は`public_threat_intel`、`scenario_author`、`system_model`、`derived`のいずれかです。導出値は元のTracePathやFlowを`source_id`で参照します。

## 9. 既存CLI/JSON互換と移行方針

既存の`trace_paths`、`mapping_gaps`、Sigma候補、`coverage`は保持します。新しいATT&CK候補は`candidate_paths`にも保存し、検知戦略がない候補の`strategy_id`は空文字とします。
既存の文字列だった`threat_analysis[].detection_feasibility`は、`status`、`reasons`、`evidence`、`evaluated_conditions`、`provenance`を持つオブジェクトへ拡張しました。従来のイベント／フィールド情報は`coverage`に残します。

`evaluate-scenarios`は固定fixtureで`multidomain-results.json`と`report.md`を再生成します。
判定境界fixtureは`scenarios/condition-fixtures.yaml`で別実行し、YAMLの`expected_outcome`と
実測した候補状態を比較します。公開脅威候補の母集団は`threat-universe.yaml`に保持し、
`evaluate-threat-universe`が固定seedで層別抽出して候補別プロファイルを評価します。

## 10. fixture/test matrix

| ケース | 適用可否 | 検知可能性 | 確認内容 |
|---|---|---|---|
| 明示Flow＋全アクセス条件＋全ログ | applicable | detectable | 全条件成立 |
| 明示Flow＋成立条件＋ログなし | applicable | unavailable | ログ不足をblockedにしない |
| Flowなし | blocked | unknown | 通信経路理由 |
| Flowあり・条件未指定 | unknown | unknown/partial | 推測しない |
| Flowあり・一部ログのみ | applicable | partial | フィールド不足 |
| 複数Flow（blocked＋applicable） | applicable | 個別評価 | 代替Flow集約 |

テストと固定fixtureは、`tests/test_applicability.py`および`evaluations/scenarios/`でこの表を再現します。
