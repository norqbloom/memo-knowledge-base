# Knowledge Base

Apache、Flask/Gunicorn、SQLite、Docker Composeで構成した、Markdown対応のロールベース・ナレッジベースです。

## 起動

`.env.example`を`.env`へコピーし、初期管理者のパスワードを変更してから起動します。

```powershell
Copy-Item .env.example .env
docker compose up --build
```

LAN内だけで公開する場合は、`.env`の`WEB_BIND_ADDRESS`をサーバのLAN側IPアドレスにすると、そのアドレス以外では待ち受けません。`0.0.0.0`のまま使用する場合は、OSやルータのファイアウォールでLAN外からの接続を拒否してください。

- ログイン画面: <http://localhost:8080/login>
- ナレッジ一覧: <http://localhost:8080>
- ユーザ管理: <http://localhost:8080/admin/users>
- ヘルスチェック: <http://localhost:8080/health>

初回起動時、ユーザが1人もいない場合だけ`.env`の`ADMIN_USERNAME`と`ADMIN_PASSWORD`から管理者を作成します。一度作成されたユーザのパスワードは、管理画面から変更してください。

## ロール

| ロール | 権限 |
| --- | --- |
| 閲覧者 | ナレッジ一覧・本文の閲覧 |
| 編集者 | 閲覧者の権限＋ナレッジの作成・編集・ゴミ箱移動／復元・Markdownプレビュー |
| 管理者 | 編集者の権限＋ユーザ作成・ロール変更・パスワード変更・削除 |

すべてのロールが同じ`/login`画面を使用します。権限判定は画面表示だけでなく、各サーバルートでも行います。

## ナレッジ機能

- タイトル・Markdown本文を対象にしたSQLite FTS5全文検索（日本語の空白なし文章に対応）
- タグによる絞り込み
- 編集画面での既存タグ候補検索と新規タグ追加
- 記事作成・更新・復元・ゴミ箱操作ごとの変更履歴
- 過去バージョンの本文・タイトル・タグの表示と復元
- 記事一覧・変更履歴・ゴミ箱を20件単位でページ分割
- 編集開始後に別ユーザが保存した場合の競合検出
- 編集／プレビュー切り替え
- 管理者による記事のCSV一括インポート・エクスポート

全文検索は3文字以上の語をSQLite FTS5のtrigramで検索し、1〜2文字の語は`LIKE`検索へ切り替えます。FTSインデックスは初回作成時または検索方式の更新時だけ再構築し、通常起動時は再構築しません。

### CSV形式

必須列は`title`と`content_md`です。`id`、`tags`、`_format`は任意です。

```csv
_format,id,title,content_md,tags
,1,Docker起動手順,"# 起動\n\ndocker compose up","Docker,運用"
,,新しい記事,"# 本文",新規タグ
```

- `id`が既存記事と一致する行は更新します。
- `id`が空欄の行は新しいIDで作成します。
- 存在しない`id`を指定した行は、そのIDで作成します。
- 複数タグはカンマで区切ります。
- 更新時に`tags`列自体を省略した場合、既存タグを維持します。
- インポートはUTF-8 CSV、最大1,000記事・5MBです。
- 全行を検証してから反映し、エラーがある場合はデータを変更しません。
- 更新された記事には新しい変更履歴を作成します。
- エクスポートは記事を1件ずつ出力するため、全記事をメモリへ読み込みません。
- 表計算ソフトの数式として解釈される値には、CSVエクスポート時に安全化用の`'`を付与します。このアプリのエクスポート形式（`_format=kb-csv-v2`）を再インポートすると、安全化用の`'`だけを自動的に取り除きます。

## セキュリティ

- パスワードはハッシュ化してSQLiteへ保存
- ログイン状態はHTTP Only・SameSite Cookieで管理
- 10分間に5回ログインに失敗した接続元とユーザ名の組み合わせを15分間制限
- すべての更新フォームをCSRFトークンで保護
- Markdownから生成したHTMLをサニタイズ
- 最後の管理者の降格・削除と、ログイン中ユーザ自身の削除を防止
- 認証画面に`no-store`を付け、CSP・クリックジャッキング防止・MIMEスニッフィング防止ヘッダを送信

この構成はLAN内のHTTP利用を前提としているため、Cookieの`Secure`属性は付けていません。インターネットへ公開する場合は、ApacheでHTTPSを設定し、`SESSION_COOKIE_SECURE`も有効にしてください。

Flask/GunicornコンテナはUID/GID `10001`の非rootユーザで動作します。以前のroot実行版で作成した`sqlite_data`ボリュームを引き継ぐ場合は、更新後の初回起動前に一度だけ所有者を変更してください。

```powershell
docker compose build app
docker compose run --rm --user root app chown -R 10001:10001 /data
docker compose up -d --build
```

依存パッケージは開発中のため互換バージョン範囲で指定しています。開発完了時に、実際に検証したバージョンへ完全固定してください。

## テスト

```powershell
python -m pip install -r app/requirements-dev.txt
python -m pytest
```

SQLiteのデータは`sqlite_data`ボリュームに残ります。通常の終了は`docker compose down`を使用してください。

SQLiteはWALモードで動作し、Apache・Flask・SQLiteの日時は`Asia/Tokyo`（JST、UTC+9）へ固定しています。
