# 營運與部署

[← README](../README.md) · [English](operations.md) · [繁體中文](operations.zh-TW.md)

## 部署

不用打包，scp 上去再重啟服務就行。下面三個變數請換成你自己的值：

```bash
PI_HOST=root@your-pi.local          # wherever the service runs
APP_DIR=/opt/claude-memory          # its install directory
SVC_USER=claudemem                  # the unprivileged user it runs as

ssh $PI_HOST "mkdir -p /tmp/memweb/web"
scp main.py webauth.py passkeys.py requirements.txt test-web.sh $PI_HOST:/tmp/memweb/
scp web/* $PI_HOST:/tmp/memweb/web/
ssh $PI_HOST "cd $APP_DIR \
  && cp -a main.py main.py.bak-\$(date +%F) \
  && $APP_DIR/venv/bin/pip install -q -r /tmp/memweb/requirements.txt \
  && install -o \$SVC_USER -g \$SVC_USER -m 644 /tmp/memweb/main.py . \
  && install -o \$SVC_USER -g \$SVC_USER -m 644 /tmp/memweb/webauth.py . \
  && install -o \$SVC_USER -g \$SVC_USER -m 644 /tmp/memweb/passkeys.py . \
  && install -o \$SVC_USER -g \$SVC_USER -m 644 /tmp/memweb/web/* web/ \
  && systemctl restart claude-memory && ./test-web.sh"
```

要回滾，執行 `cp -a main.py.bak-<date> main.py && systemctl restart claude-memory`。分類的每次寫入都會在 `data/` 裡做 git commit，所以改壞了也能從 `/memory/{cat}/history` 和 `?rev=<sha>` 救回來。

發佈 JS 或 CSS 時，記得調高 `index.html` 裡 `<script>`/`<link>` 標籤的 `?v=` 參數，不然瀏覽器會一直用舊的快取檔。

## 多個執行個體

同一個程式碼目錄可以服務多個完全獨立的儲存庫：每位使用者各跑一個行程，各自用自己的 port 和主機名稱。執行個體擁有的每樣東西都由環境變數指定；沒設的話，就退回程式碼旁邊的同名檔案，單一安裝一直都是這樣運作。

| 變數 | 預設值（程式碼旁邊） | 說明 |
|---|---|---|
| `MEMORY_ENV_FILE` | python-dotenv 往上層目錄搜尋到的檔案 | 這個執行個體的 `.env` |
| `MEMORY_DATA_DIR` | `data/` | 分類、`docs/`、git 歷史 |
| `MEMORY_AUTH_FILE` | `auth.json` | 登入提供者、允許清單、`keyver` |
| `MEMORY_KEYS_FILE` | `apikeys.json` | 具名的 `mem_` 金鑰 |
| `MEMORY_PASSKEY_FILE` | `passkeys.json` | 已註冊的 passkey（只存公開金鑰） |
| `MEMORY_OAUTH_FILE` | `mcpoauth.json` | MCP 連接器的授權記錄 |
| `MEMORY_PUBLIC_URL` | 請求的 Host | `/mcp` 的 issuer / resource URL；`MEMORY_RP_ID` 沒設時，也是 passkey 的 RP id |
| `MEMORY_RP_ID` | `MEMORY_PUBLIC_URL` 的 host；兩者都沒設就關閉 passkey | passkey 的 relying-party id：公開主機名稱，絕不取自 Host header |
| `MEMORY_RP_ORIGIN` | `https://<MEMORY_RP_ID>`（id 取自 `MEMORY_PUBLIC_URL` 時，則是它的 origin） | passkey 流程唯一接受的來源 origin |
| `MEMORY_SESSION_KEY` | 由 `CLAUDE_MEMORY_TOKEN` 衍生 | 簽署 Cookie 用的祕密 |
| `MEMORY_INSTANCE_NAME` | `owner` | 這是誰的記憶庫：會出現在 `/mcp` 的 serverInfo 與說明、list/index 輸出、授權同意頁 |
| `MEMORY_FLAG_DIR` | `MEMORY_DATA_DIR` 的上一層 | `READONLY` / `ALERT` 複寫旗標（見 `replflag.py`） |
| `MEMORY_NODE` | 未設定 | 每個回應都帶 `X-Memory-Node`，讓 watchdog 能分辨公開主機名稱現在連到哪個節點 |
| `MEMORY_READONLY_CATEGORIES` | 未設定 | 以逗號分隔的分類清單，所有用戶端憑證都只能讀，不能 PUT/DELETE（回 403）；例如親屬的 `protocol`，由 `replication/memprotocol-sync` 產生 |

只要程式碼目錄裡還放著另一個執行個體的 `.env`，就要設定 `MEMORY_ENV_FILE`。python-dotenv 不會覆蓋已經設好的變數，但會補上所有缺的；第二個執行個體不設的話，就會繼承第一個的 `MEMORY_PUBLIC_URL` 或提供者設定。每個執行個體都要有自己的 `CLAUDE_MEMORY_TOKEN`；一個執行個體的 token、Cookie、`mem_` 金鑰和 `mcpa_` token，其他執行個體一律拒絕。

樣板化的 unit（`claude-memory@.service`）必須列出每個執行個體專屬的檔案，`MEMORY_PASSKEY_FILE` 也不能漏：沒設的話，共用程式碼目錄的執行個體會去讀程式碼旁邊屬於 owner 的 `passkeys.json`；而狀態目錄在別處的備援機，也永遠看不到複寫過去的 passkey。

## 把 /mcp 轉送到另一個 MCP 伺服器

設定 `MEMORY_MCP_UPSTREAM` 後，這個執行個體會變成帶驗證的代理：先用一般的 token / `mem_` 金鑰 / OAuth 授權檢查 `POST /mcp`，再把 JSON-RPC 本體原封不動轉給無狀態的 Streamable HTTP MCP 伺服器，並把它的回覆原封不動傳回去。沒設（預設）時，`/mcp` 留在本機處理。呼叫端的憑證不會離開這個執行個體：上游只會看到 `MEMORY_MCP_UPSTREAM_KEY_FILE` 裡的金鑰（每次呼叫都重讀）、固定的 `User-Agent`，以及放在 `X-Forwarded-Actor` 的操作者。

| 變數 | 預設值 | 說明 |
|---|---|---|
| `MEMORY_MCP_UPSTREAM` | 未設定 | 上游的 `POST` URL；須為 `http://` 或 `https://`，其他協定只會記一行 log，等於關閉 |
| `MEMORY_MCP_UPSTREAM_KEY_FILE` | 未設定 | 存放上游 bearer 的檔案；每次請求都重讀，並去掉空白 |
| `MEMORY_MCP_UPSTREAM_TIMEOUT` | `140` | 上游逾時秒數，限制在 1..600 之間 |
| `MEMORY_CONSENT_LABEL` | 記憶庫名稱 | 兩個授權同意頁用來取代記憶庫名稱的文字 |

上游失敗時，會轉成 JSON-RPC 錯誤（`-32000`）搭配 502（逾時是 504，缺金鑰是 503）。上游回 401/403 時，不會以 401 傳給呼叫端，這樣連接器才不會重跑 OAuth 登入；3xx 不會跟隨。有範圍限制的 `dst_` token 會被拒絕（403），未驗證的呼叫也不會轉出任何東西。`GET`/`DELETE /mcp` 仍然回 405。
