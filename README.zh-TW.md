[English](README.md) · **繁體中文**

# claude-memory-web

專為 Claude 設計的個人長期記憶庫 —— 一個小型的 FastAPI 服務，用於儲存分類的 Markdown 筆記，在每次寫入時進行 git commit，並在 `/mcp` 作為 [MCP 伺服器](#連接-claude-mcp) 提供給 Claude，讓所有 Claude 工作階段（任何機器上的 Claude Code、claude.ai、Claude 應用程式）都能讀寫同一份記憶。同一個應用程式也在 `/` 為使用者提供瀏覽器 UI，因此沒有 CORS 問題、不需要第二台主機，也無需任何建置步驟。

原生 JavaScript（Vanilla JS）、無 npm、無 CDN、無相依套件。它在 Raspberry Pi 4 上執行。

![no build step](https://img.shields.io/badge/build-none-informational)

## 連接 Claude (MCP)

`POST /mcp` 是一個 Model Context Protocol 伺服器（Streamable HTTP、無狀態、純 JSON 回應），將儲存庫公開為八個工具：`memory_list`、`memory_index`、`memory_search`、`memory_get`、`memory_write`、`memory_delete`、`memory_history`、`memory_pins`。這就是 Claude 存取儲存庫的方式；無需安裝用戶端，用戶端也無需維護任何更新，因為所有工具及其說明皆由伺服器提供。

- **claude.ai / Claude 應用程式**：Settings → Connectors → Add custom connector，URL 填入 `https://<host>/mcp`。Claude 會自動註冊自身（RFC 7591），將你導向至 `/oauth/authorize`，以 Google/GitHub 登入後點擊 Allow。該連線會列在 UI 的 MCP 頁面（`/#/keys`）中的 *Connected apps* 底下，亦可在此處中斷連線。
- **Claude Code**：在 MCP 頁面簽發一把金鑰，頁面會直接提供組好的指令：

  ```bash
  claude mcp add --transport http --scope user memory https://<host>/mcp \
    --header "Authorization: Bearer <mem_ key>"
  ```

  省略 `--header` 則會改透過 loopback 重新導向進行相同的 OAuth 登入。

每個工具都在同一個行程內呼叫底層的 [REST 路由](#此-api-是什麼)，因此 ETag 前置條件、roster 檢查機制與 git commit 皆完全適用。寫入時需要帶入 `memory_get` 回傳的 `etag`；沒有任何用戶端快取可以依賴。

`mcpoauth.py` 為授權伺服器。依規範要求開放註冊，但授權碼僅會在已登入的擁有者點擊 Allow 後，才重新導向至 Claude 自身的 callback 或 loopback URI，且僅限持有 PKCE verifier 的請求者。Access token 效期為一小時，且僅被 `/mcp` 接受 —— 絕不被 REST API 接受。Refresh token 效期為自上次使用起 90 天且不進行輪替（請參閱該模組的 docstring）。授權記錄存於 `mcpoauth.json`（權限 600，僅存雜湊值）。若 Host 標頭不再是公開名稱，請設定 `MEMORY_PUBLIC_URL`。

## 此 API 是什麼

在 MCP 工具與瀏覽器 UI 底層的是同一個 REST API；兩者都呼叫它，且兩者都不重新實作其任何規則。它為每個分類儲存一個 Markdown 檔案，由單一 bearer token 保護，並在每次寫入時進行 git commit，確保任何編輯皆可復原。讀取為 `GET /memory/{category}`；寫入需要帶有先前讀取到的 ETag 的 `If-Match`，該 ETag 即為本體的 git blob SHA。這裡的 `main.py` 與 `webauth.py` 即構成了整個伺服器。

該 ETag 是**磁碟上**位元組的 blob SHA，且每個讀取路徑 —— 分類、文件以及兩種索引列表 —— 都以與寫入防護相同的方式計算它。搞錯這點會引發難以察覺且棘手的問題：如果改為雜湊**解碼後的**文字，通用換行符號（universal-newline）轉換就會介入，導致以 CRLF 儲存的檔案以 LF 形式提供，並依據 LF 形式計算雜湊。如此一來，如實回傳所接收 ETag 的用戶端將永遠被以 `409 etag mismatch` 拒絕，即使根本沒有任何並行寫入者也是如此。因此，請求本體會正規化為 LF，且必須是有效的 UTF-8，否則寫入將被拒絕並回傳 `400` —— 若沒有這項檢查，一個損壞的本體就會破壞整個儲存庫的 `index`、`search` 和 `pins`，因為這三者都會讀取所有檔案。`tests/test_etag_crlf.py` 確保了這項約定。

系統共有兩個命名空間。`/memory/{category}` 存放事實（facts）—— 簡短、去重複、單一主題。`/docs/{slug}` 存放工作文件 —— 交接紀錄（handoffs）、操作手冊（runbooks）、稽核報告：篇幅長、專案範圍、採取代換而非累加。文件存放在 `data/docs/` 中，所有 `/memory` 端點都看不到它們，因為其 glob 比對是非遞迴的。除非傳入 `&scope=docs|all`，否則 `/memory/search` 會略過文件，因此交接文本絕不會淹沒事實查詢。

搜尋預設回傳包含所有詞彙的每一行。`&mode=rank` 則以 BM25 對整個區段排序（OR 語意、輕度詞幹化、CJK 雙字詞；見純 Python 的 `searchrank.py`），因此文本恰好沒用到的某個詞不再讓結果歸零，且每筆結果都會列出它 `matched` 的詞。索引由 Markdown 衍生，檔案變動時重建。稠密向量（dense embeddings）曾評估後暫緩：在共用的 Pi 上多掛約 150 MB 的執行環境，對一個約 1 MB、且讀者能自行改寫查詢的語料庫而言，比 BM25 多得的效益很少。

兩個命名空間在 GET、PUT 和 DELETE 上皆支援 `?section=<name>`，用於定位單一 `## ` 區塊：從 20 KB 的檔案中讀取三行，或將三行接合回去而不更動任何其他位元組。鎖定單位仍是整個檔案 —— `If-Match` 依舊攜帶整檔的 ETag —— 僅有*編輯*單位變成了區段（section）。這對 LLM 呼叫端至關重要，否則它們為了修改一行就得載入整個分類，並手動建構整檔修補檔（patch）寫回。若請求本體的標題與區段不符，會回傳 `400`，絕不進行隱式重新命名，因為靜默重新命名會破壞所有指向舊名稱的現有參照。

## UI 的功能

- **側邊欄樹狀圖** —— 儲存結構是扁平的（名稱符合 `^[a-z0-9-]+$`），但命名慣例為 `<parent>-<sub>`，因此層級是透過最長前綴比對還原：`infra-pc-tuning` 會巢狀收合在 `infra-pc` 下，而非 `infra`。折疊狀態會被保留；過濾與導覽會強制展開祖先節點而不會覆寫該狀態。
- **閱讀檢視** —— 算繪後的 Markdown，具備區段大綱，並透過 `<!-- verified: YYYY-MM-DD -->` 標記驅動時效性徽章。
- **編輯器** —— 具備捲動同步的即時預覽。透過隱藏的鏡像元素測量每個自動折行（soft-wrapped）原始碼行的實際位置，並固定兩端的捲動極限，因此即使算繪區塊與原始碼行的高度不同，窗格也能保持對齊。
- **並行控制** —— 儲存時會攜帶載入文件時的 ETag。若發生 `409` 會開啟差異比較（diff），提供*載入對方的版本*、*以我的版本覆寫*或*繼續編輯*等選項。絕不會有任何內容被靜默覆蓋。
- **草稿** —— 輸入時文字會即時鏡像至 `localStorage`，因此關閉分頁也不會遺失內容。
- **歷史紀錄** —— git 修訂版本、單一修訂檢視、與目前版本比較差異，以及作為前向 commit 進行還原（絕不重寫歷史）。
- **搜尋** —— 跨整個語料庫搜尋，並支援跳轉至指定行。
- **MCP 頁面** —— 說明如何連接 claude.ai 與 Claude Code、簽發與刪除金鑰（每把新金鑰皆附帶其 `claude mcp add` 指令），以及已連線應用程式清單與中斷連線按鈕。

## 驗證機制

入口有兩種，兩者刻意不對稱。

**Agent** —— 透過 MCP 連線的 Claude —— 提供 bearer 憑證：一把 `mem_` 金鑰或來自連接器（connector）流程的 OAuth 授權，永遠不會被要求第二因子。持有者本來就能讀寫整個儲存庫，因此在瀏覽器這道門加上第二因子並不能守住任何東西。

**使用者** 使用 GitHub 或 Google 登入，讓手機能在不持有 token 的情況下讀取儲存庫。第二因子即為該帳號上既有的保護；`auth.json` 中的電子郵件允許清單則是授權步驟，因為單純「使用 GitHub 登入」只代表對方擁有任何一個 GitHub 帳號。`GET /auth/<provider>` 會啟動授權碼（authorization-code）交握，回呼（callback）則透過直接對提供者發起的後端通道呼叫交換授權碼。這也是此處不驗證 token 簽章、且整個流程無需加入任何相依套件的原因：本服務與提供者的 token 端點之間沒有任何中介，而這正是 JWT 驗證所要確立的特性。

兩個提供者皆可設定，亦可僅設定其中之一；未設定或允許清單為空的提供者即為關閉狀態，其按鈕會被隱藏，且路由會回應 503。兩者之間有兩項實質而非表面上的差異：**GitHub OAuth App 會忽略 PKCE**，因此 `code_challenge` 僅傳送給 Google，GitHub 的交握純粹依賴簽章後的 state cookie 與 client secret 來維繫；且 **GitHub 會將被拒絕的 code 交換回傳為帶有 `error` 本體的 HTTP 200**，因此無法利用狀態行來區分成功或失敗。GitHub 的身分識別來自 `GET /user/emails`（回傳帳號上的所有電子郵件地址），因此允許清單是與已驗證的地址進行比對。

兩條路徑最終都會取得同一個 Cookie。帶有 token 的 `POST /auth/login` 依然可用，且在 Google 無法連線、允許清單錯誤或沒有瀏覽器可執行同意畫面時，是重新取回存取權的後路。

該 Cookie 具備 HttpOnly，並以從 API token 衍生的金鑰進行簽章，因此輪替 token 會使所有瀏覽器登出，且無需管理第二個密鑰。`auth.json` 中的 `keyver` 是不更動 token 時的同等機制：遞增它即可讓所有瀏覽器工作階段失效，同時讓所有 agent 繼續正常運作（`manage_auth.py sign-out-everyone`）。

### 金鑰

已登入的瀏覽器可在 MCP 頁面（`/#/keys`）簽發具名稱的 bearer 金鑰 —— 一台裝置或一個 agent 一把。金鑰的讀寫權限與 master token 完全相同，但刪除它不會影響其他任何東西，這正是遺失手機時能夠單獨處置、而無需輪替 token 並將所有瀏覽器與 agent 一併強制登出的原因。

金鑰無法簽發或刪除金鑰。該操作僅限 Cookie，因此外洩的金鑰無法自行簽發出比它自身撤銷後還活得更久的接班金鑰。秘密僅顯示一次且絕不儲存 —— `apikeys.json`（權限 600，位於 `main.py` 旁，絕不放入 `data/` 內）只存放其 SHA-256。256 位元的 `secrets.token_urlsafe` 不需要慢速 KDF；沒有任何暴力破解的空間。

Claude Code 正是將金鑰作為 `Authorization: Bearer <key>` 發送至 `/mcp`；頁面會在新的密鑰旁顯示準備就緒的 `claude mcp add` 指令。

### 設定提供者

針對 GitHub，請在 <https://github.com/settings/developers> 註冊一個 OAuth App，授權回呼 URL 填寫 `https://<your host>/auth/github/callback`；client id 與 secret 會立即發放。針對 Google，請在 <https://console.cloud.google.com/apis/credentials> 建立一個 OAuth **Web application** 用戶端，重新導向 URI 填寫 `https://<your host>/auth/google/callback`（此項需先填寫同意畫面表單）。接著在主機上執行：

```bash
sudo -u claudemem $APP_DIR/venv/bin/python $APP_DIR/manage_auth.py \
     setup github <client-id> https://<your host>/auth/github/callback you@example.com
```

允許清單上的地址必須是提供者會回報為已驗證的地址 —— 對 GitHub 而言，這代表必須是 <https://github.com/settings/emails> 上的地址，而非 `users.noreply.github.com` 別名。

指令會在終端機上提示輸入 client secret，而不是從 `argv` 接收，並將 `auth.json` 以權限 600 寫入 `main.py` 旁 —— 絕不放在 `data/` 內，因為後者是一個會永久保留其中每個檔案所有版本的 git 儲存庫。無需重新啟動：檔案內容變更時會自動重新讀取。

若完全不設定任何提供者，服務的行為將與以往完全相同 —— 登入頁面會提供 token 欄位，且 `/auth/<provider>` 會回應 503。

透過 Cookie 授權的寫入還必須發送 `X-Memory-Actor`；跨站請求無法設定自訂標頭，且該 Cookie 還額外設定了 `SameSite=strict`。此標頭同時兼作 git commit 中的作者（`PUT infra via memory-web`）。

登入會依用戶端 IP 進行速率限制。FastAPI 內建的 `/docs`、`/redoc` 與 `/openapi.json` 皆已停用 —— 在公開主機名稱上，結構定義（schema）是唯一無需驗證即可讀取的內容，且 `/docs` 現已作為前述的工作文件命名空間。

## 檔案

| Path | Deployed to | What |
|---|---|---|
| `main.py` | `$APP_DIR/main.py` | API，加上 `/auth/*` 與靜態掛載 |
| `webauth.py` | `$APP_DIR/webauth.py` | HMAC Cookie 工作階段、OAuth 提供者表格、登入速率限制 |
| `manage_auth.py` | `$APP_DIR/manage_auth.py` | 管理 `auth.json`：提供者用戶端、允許清單、`keyver` |
| `apikeys.py` | `$APP_DIR/apikeys.py` | 具名稱、可撤銷的 bearer 金鑰，由瀏覽器簽發 |
| `mcpserver.py` | `$APP_DIR/mcpserver.py` | `/mcp`：JSON-RPC 分派與八個工具 |
| `mcpoauth.py` | `$APP_DIR/mcpoauth.py` | `/mcp` 的 OAuth 2.1 伺服器：註冊、授權碼、授權記錄 |
| `web/` | `$APP_DIR/web/` | `index.html`、`app.css`、`app.js`、`md.js`、`diff.js` |
| `test-web.sh` | `$APP_DIR/test-web.sh` | 伺服器測試套件，於主機上執行 |
| `tests/` | `$APP_DIR/tests/` | 單元測試：`test_webauth.py`（離線）、`test_etag_crlf.py`；`test_mcp_live.py` 針對執行中的應用程式測試完整連接器流程；`test_isolation_live.py` 驗證兩個執行個體會相互拒絕彼此的憑證 |
| `devstub.py` | — | 本地 UI 開發用的假後端，僅限開發使用 |
| `rendertest.js` | — | 針對 `md.js` / `diff.js` 的 28 項檢查，僅限開發使用 |
| `fixtures/` | — | 算繪測試所執行的合成語料庫 |

## 開發

```bash
python devstub.py     # serves web/ on :8123 with a fake API, no token needed
node rendertest.js    # markdown + diff checks
python tests/test_webauth.py   # sessions, keyver, PKCE state, allowlist; no network
python tests/test_apikeys.py   # minting, verifying, revoking; no network
```

`devstub.py` 從記憶體中的測試資料（fixtures）模擬整個 API，包含一個寫入永遠回傳 `409` 的分類，以便在沒有伺服器的情況下測試衝突處理 UI。

放置於最頂層目錄的真實分類會被作為額外的算繪測試輸入，且已被加入 gitignore —— 它們是個人筆記，而非測試資料。

## 部署

無需打包步驟；只需 scp 並重新啟動。請將以下變數設為你自己的值：

```bash
PI_HOST=root@your-pi.local          # wherever the service runs
APP_DIR=/opt/claude-memory          # its install directory
SVC_USER=claudemem                  # the unprivileged user it runs as

ssh $PI_HOST "mkdir -p /tmp/memweb/web"
scp main.py webauth.py test-web.sh $PI_HOST:/tmp/memweb/
scp web/* $PI_HOST:/tmp/memweb/web/
ssh $PI_HOST "cd $APP_DIR \
  && cp -a main.py main.py.bak-\$(date +%F) \
  && install -o \$SVC_USER -g \$SVC_USER -m 644 /tmp/memweb/main.py . \
  && install -o \$SVC_USER -g \$SVC_USER -m 644 /tmp/memweb/webauth.py . \
  && install -o \$SVC_USER -g \$SVC_USER -m 644 /tmp/memweb/web/* web/ \
  && systemctl restart claude-memory && ./test-web.sh"
```

復原（Rollback）指令為 `cp -a main.py.bak-<date> main.py && systemctl restart claude-memory`。分類寫入會在 `data/` 中進行 git commit，因此錯誤的編輯可透過 `/memory/{cat}/history` 與 `?rev=<sha>` 來復原。

發布 JS 或 CSS 時，請遞增 `index.html` 中 `<script>`/`<link>` 標籤上的 `?v=` 查詢參數，否則瀏覽器會繼續提供舊的快取複本。

## 執行多個執行個體

單一程式碼目錄可以支援多個完全獨立的儲存庫 —— 每個使用者一個行程，各自擁有專屬的連接埠與主機名稱。執行個體所屬的一切項目皆由環境變數指定；若未設定，則會回退到程式碼旁的檔案，這也是單一安裝一直以來的運作方式。

| Variable | Default (next to the code) | What |
|---|---|---|
| `MEMORY_ENV_FILE` | python-dotenv 向上搜尋 | 此執行個體的 `.env` |
| `MEMORY_DATA_DIR` | `data/` | 分類、`docs/`、git 歷史紀錄 |
| `MEMORY_AUTH_FILE` | `auth.json` | 登入提供者、允許清單、`keyver` |
| `MEMORY_KEYS_FILE` | `apikeys.json` | 具名稱的 `mem_` 金鑰 |
| `MEMORY_OAUTH_FILE` | `mcpoauth.json` | MCP 連接器授權記錄 |
| `MEMORY_PUBLIC_URL` | 請求的 Host | `/mcp` 的簽發者（issuer）/ 資源 URL |
| `MEMORY_SESSION_KEY` | 由 `CLAUDE_MEMORY_TOKEN` 衍生 | Cookie 簽署密鑰 |
| `MEMORY_INSTANCE_NAME` | `owner` | 所屬保險庫：顯示於 `/mcp` serverInfo 與說明指引、list/index 輸出、同意畫面 |
| `MEMORY_FLAG_DIR` | `MEMORY_DATA_DIR` 的父目錄 | `READONLY` / `ALERT` 複寫旗標（參見 `replflag.py`） |
| `MEMORY_NODE` | 未設定 | 包含在每個回應的 `X-Memory-Node` 標頭中，讓 watchdog 能識別公開主機名稱連到哪個節點 |
| `MEMORY_READONLY_CATEGORIES` | 未設定 | 以逗號分隔的分類清單，所有用戶端憑證皆可讀取但不可 PUT/DELETE（403）；親友的 `protocol`，由 `replication/memprotocol-sync` 算繪 |

當程式碼目錄中同時包含另一個執行個體的 `.env` 時，請設定 `MEMORY_ENV_FILE`：python-dotenv 絕不會覆寫已設定的變數，但會填補所有缺失的變數，否則第二個執行個體將會繼承第一個執行個體的 `MEMORY_PUBLIC_URL` 或提供者設定。每個執行個體都需要各自的 `CLAUDE_MEMORY_TOKEN`；任何一個執行個體的 token、Cookie、`mem_` 金鑰與 `mcpa_` token 都會被其他執行個體拒絕。

## 備註

- 靜態掛載必須保持為 `main.py` 中的**最後一條**陳述式。Starlette 依宣告順序比對路由；若過早加入掛載於 `/` 的路由，將會吞沒 `/memory/*`。
- `md.js` 是特意設計的子集算繪器，而非完整的 Markdown 函式庫：它會先跳脫所有內容以確保筆記不會變成可執行的 HTML、不支援 `_underscore_` 強調語法（語料庫中充斥著 `snake_case` 識別碼），並將 `<!-- verified: DATE -->` 轉換為時效性徽章而非直接丟棄。
- `test-web.sh` 在執行前會重新啟動服務，使記憶體中的登入速率限制計數器歸零；速率限制測試排在最後，因為它會耗盡該時間視窗的額度。

## 授權條款

MIT。
