# ATT&CK経路の適用可否・検知可能性判定仕様

この文書は、`run_pipeline` が生成した各 `TracePath` を再現可能に評価するための詳細仕様である。攻撃が成立し得るか (`attack_applicability`) と、成立した経路を現在のテレメトリで検知できるか (`detection_feasibility`) は別の判定であり、後者の不足で前者を `blocked` にしてはならない。

## 1. 用語・状態定義

- **TracePath**: `CVE → CWE → CAPEC → ATT&CK technique → Detection Strategy` の一意な経路。CVEを入口にしないシナリオでは空のCVE/CWE/CAPECを持つ。
- **候補Flow**: 対象Assetを `to` とする明示的な `Flow`。同じTracePathに複数候補がある場合も個別評価する。
- **attack_applicability**: 対象システムでその経路が成立し得るか。
  - `applicable`: 1つ以上の候補Flowで全条件が `satisfied`
  - `blocked`: 全候補Flowが `blocked`、または候補Flowがなく到達性が明示的に成立しない
  - `unknown`: `blocked` がなく、少なくとも1つの条件が `unknown`
- **detection_feasibility**: 成立し得る経路に必要な観測が揃っているか。
  - `detectable`: 必須テレメトリ、フィールド、認証ログ、logsourceが利用可能
  - `partial`: 利用可能なものと不足するものが混在
  - `unavailable`: 不足があり、利用可能な必須テレメトリがない
  - `unknown`: 取得状況自体が宣言されていない

Applicability条件は `satisfied / blocked / unknown`、検知条件は `available / missing / unknown` で評価する。

## 2. 入力フィールドと出典の優先順位

入力は `SystemModel`、`ScenarioContext`、ATT&CK Detection Requirement の明示値だけを使う。値を製品名、プロトコル名、ゾーン名から補完しない。

| 入力 | 判定に使う内容 | provenance の `source_type` |
|---|---|---|
| `Asset.trust_zone`, `privilege_level`, `logs`, `logsource`, `exposed_to` | 境界、権限、テレメトリ、外部到達元 | `system_model` |
| `Flow.from/to`, `trust_boundary`, `authentication`, `authorization` | 到達性とアクセス条件 | `system_model` |
| `ScenarioContext.required_privilege`, `privilege_transition`, `authentication`, `authorization`, `required_authentication_logs` | 評価条件と認証ログ | `scenario_author` |
| ATT&CK technique / Detection Strategy / Analytic | 検知に必要なData Component、event、field | `public_threat_intel` |
| 集約したstatus | 上記の条件から導出した結果 | `derived` |

同じ項目に複数の明示値がある場合は、個別の証拠を捨てず、候補別・条件別に保存する。`derived` の証拠には元の `source_id` を参照できる provenance を含める。

## 3. `attack_applicability` の判定順序、三値評価、集約表

各候補Flowを次の順序で評価する。

1. **reachability**: 対象Assetへ向かう明示的なFlowがあるか。Flowがない場合は `blocked`。送信元がAssetまたは `exposed_to` に明示されていない場合は `unknown`。
2. **trust_boundary**: `required_trust_boundary` があればFlowと一致する必要がある。一致しない場合は `blocked`、必要境界が未指定の場合は `unknown`。Flowに境界が明示され、経路と矛盾しない場合だけ `satisfied`。
3. **authentication**: `required: false` の一致は `satisfied`。`required: true` は、シナリオ側に `satisfied: true` が明示されない限り `unknown`。明示的な不一致は `blocked`。
4. **authorization**: 認証と同じ規則で `roles`、`scopes`、`privilege` の明示値も比較する。
5. **privilege**: `required_privilege` と対象Assetの `privilege_level` を比較し、明示的な不足は `blocked`。`privilege_transition` は送信元・対象Assetの明示レベルと比較する。不足は `unknown`。

1候補Flowの集約は次のとおりである。

| 条件集合 | Flowのstatus |
|---|---|
| `blocked` が1つ以上 | `blocked` |
| `blocked` はなく `unknown` が1つ以上 | `unknown` |
| 全条件が `satisfied` | `applicable` |

複数FlowのTracePath集約は、1つでも `applicable` なら `applicable`、全て `blocked` なら `blocked`、それ以外は `unknown` とする。

## 4. `detection_feasibility` の判定順序と集約表

1. Detection Strategy / AnalyticのData Component、event、fieldと、シナリオの`required_logs` / `required_telemetry`をrequired setにする。
2. `Asset.logs`、`ScenarioContext.available_telemetry`、`available_log_fields`、`Asset.logsource`をavailable setにする。
3. 必須認証ログを独立したrequired telemetryとして比較する。
4. 必要フィールドはイベントが存在しても、フィールドの取得が明示されていなければ `unknown` とする。
5. Assetのlogsourceが必要イベントに対応するかを確認する。

| 条件集合 | status |
|---|---|
| 全条件が `available` | `detectable` |
| `missing` があり、他の必須観測が一部 `available` | `partial` |
| `missing` があり、必須観測が1つも `available` でない | `unavailable` |
| 取得状況が宣言されていない | `unknown` |

この判定は攻撃適用可否を変更しない。例えば、`process_creation` が取得されていなくても、Flow・境界・認証・認可・権限が成立すれば `attack_applicability=applicable` のまま記録する。

## 5. 複数Flow・複数TracePathの扱い

各Flowは `candidate_flows` に `flow_id`、両端、条件別status、reason、evidenceを持って保存する。代替Flowの検知可能性は同じTracePathの検知要件に対して評価するが、Flow候補と混ぜない。

TracePath同士は混ぜない。`analysis.json.trace_paths` と `threat_analysis` はTracePath単位で出力し、全体の分布や削減率はこの個別結果から集計する。

## 6. `blocked` と `unknown` を分ける具体例

### blocked

対象Assetの `privilege_level=guest`、シナリオの `required_privilege=admin` が明示されている場合、権限条件は `blocked` である。Flow自体が存在しない場合の到達性も `blocked` である。明示された認証条件が `required: false` なのに、シナリオが認証必須を明示する場合も `blocked` である。

### unknown

Flowの `authentication` が未指定、またはFlowは認証必須だが攻撃者が条件を満たす証拠がない場合、認証条件は `unknown` である。HTTPSであること、`dmz` から `internal` へ向かうこと、Flowが存在することだけから認証済み・認可済みとは推測しない。

## 7. 攻撃は成立するが検知不能な具体例

次の入力を考える。

```yaml
scenario:
  scenario_type: malware
  entrypoint_type: technique
  technique_ids: [T1059]
  required_privilege: user
  authentication: {required: false}
  authorization: {required: false}
  required_logs: [{event_type: process_creation, fields: [process.command_line]}]
assets:
  - name: endpoint
    trust_zone: dmz
    privilege_level: user
    logs: [network_connection]
flows:
  - from: internet
    to: endpoint
    trust_boundary: internet-to-dmz
    authentication: {required: false}
    authorization: {required: false}
```

この場合、明示的な到達性、境界、認証、認可、権限が揃うため `attack_applicability=applicable` である。一方、必要なProcess Creationがないため `detection_feasibility=unavailable` となる。後者を理由にTracePathや`mapping_gaps`を削除してはならない。

## 8. provenance / evidence schema

各 evidence は次の形を持つ。

```json
{
  "kind": "flow | asset | scenario | telemetry",
  "id": "flow-1:internet->endpoint",
  "field": "authentication.required",
  "value": false,
  "provenance": {
    "source_type": "system_model | scenario_author | public_threat_intel | derived",
    "source_id": "flow:flow-1:internet->endpoint",
    "field": "authentication.required",
    "rationale": "この値が判定に必要な理由"
  }
}
```

`attack_applicability` と `detection_feasibility` の両方に `reasons`、`evidence`、`evaluated_conditions`、`provenance` を出力する。derived結果は元のFlow、Asset、Scenario、ATT&CKのprovenanceと同じオブジェクト内に残す。

## 9. 既存CLI/JSON互換と移行方針

既存の `run_pipeline` の引数、CVEからSigmaまでの経路、`mapping_gaps`、`coverage`、Sigma候補、終了コードは変更しない。`TracePath.to_mapping()` の既存キーは残し、新しく `trace_id`、`attack_applicability`、`detection_feasibility` を追加する。

従来の `coverage` はData Componentとシナリオの正規化イベントを比較する互換用の詳細である。新しい `detection_feasibility` はATT&CK Analyticのイベント・フィールド、認証ログ、Asset.logsourceまで含めた判定であり、両者のstatusが異なることがある。この差は意図的で、`detection_feasibility` がより厳密な判定である。

新しい `detection_feasibility` はstatusだけでなく根拠を持つオブジェクトである。旧来の文字列読み手向けに、同じレコードへ `detection_feasibility_status`（旧文字列と同じ値）を併記する。移行後は `detection_feasibility.status` を使用する。

## 10. fixture/test matrix

| ケース | applicability | feasibility | 主な確認 |
|---|---|---|---|
| 全条件とログ・fieldが明示 | `applicable` | `detectable` | 5条件と全取得条件が`satisfied/available` |
| Flowなし、境界不一致、認証・認可不一致、権限不足、遷移不成立 | `blocked` | 独立評価 | 各blocked理由を保持 |
| 認証、境界、権限の情報不足 | `unknown` | 独立評価 | HTTPS等から補完しない |
| 攻撃条件は成立、required telemetryなし | `applicable` | `unavailable` | 候補を削除しない |
| 一部のログまたはfieldのみ | 独立評価 | `partial` | available/missingを混在保存 |
| 取得状況を宣言しない | 独立評価 | `unknown` | 不明と不足を区別 |
| 複数Flow | Flow集約 | 候補別保持 | 1つのapplicableでTracePathはapplicable |
| 既存CVE fixture / CLI | 既存互換 | 既存互換 | `mapping_gaps`、Sigma、offline E2E |
