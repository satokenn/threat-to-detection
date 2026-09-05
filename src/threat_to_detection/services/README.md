# services

Collector、Mapper、Analyzerを処理順に組み合わせるアプリケーション層です。

CLIから呼び出す処理や、対象システム単位の一連のワークフローはここに置きます。各ステージの詳細な判断は、対応するcollector・mapper・analyzerへ分離します。
