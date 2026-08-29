[English](README.md) · **繁體中文**

# claude-memory-web

個人 [Claude Memory API](#此-api-是什麼) 的瀏覽器使用者介面 —— 一個小型 FastAPI 服務，用於儲存分類的 Markdown 筆記，讓 Claude 工作階段能跨機器共享長期記憶。本儲存庫新增了一個由同一個應用程式在 `/` 提供服務的前端，因此沒有 CORS 問題、不需要第二個主機，也無需任何建置步驟。

原生 JavaScript（Vanilla JS）、無 npm、無 CDN、無相依套件。它在 Raspberry Pi 4 上運行。

![no build step](https://img.shields.io/badge/build-none-informational)

## 此 API 是什麼

後端為每個分類儲存一個 Markdown 檔案，由單一 Bearer Token 保護，並在每次寫入時進行 git commit，確保任何編輯皆可復原。讀取請求為 `GET /memory/{category}`；寫入請求需要帶有先前讀取到的 ETag 的 `If-Match`，該 ETag 即為本體（body）的 git blob SHA。這裡的 `main.py` 與 `webauth.py` 即構成了整個伺服器。

該 ETag 是**磁碟上**位元組的 blob SHA，且每個讀取路徑 —— 分類、文件以及兩種索引列表 —— 都以與寫入防護相同的方式計算它。搞錯這點會引發難以察覺且棘手的問題：如果改為雜湊**解碼後的**文字，通用換行符號（universal-newline）轉換就會介入，導致以 CRLF 儲存的檔案以 LF 形式提供，並依據 LF 形式計算雜湊。如此一來，如實回傳所接收 ETag 的用戶端將永遠被以 `409 etag mismatch` 拒絕，即使根本沒有任何並行寫入者也是如此。因此，請求本體會正規化為 LF，且必須是有效的 UTF-8，否則寫入將被拒絕並回傳 `400` —— 若沒有這項檢查，一個損壞的本體就會破壞整個儲存庫的 `index`、`search` 和 `pins`，因為這三者都會讀取所有檔案。`tests/test_etag_crlf.py` 確保了這項約定。

系統共有兩個命名空間。`/memory/{category}` 存放事實（facts）—— 簡短、去重複、單一主題。`/docs/{slug}` 存放工作文件 —— 交接紀錄（handoffs）、操作手冊（runbooks）、稽核報告：篇幅長、專案範圍、採取代換而非累加。文件存放在 `data/docs/` 中，所有 `/memory` 端點都看不到它們，因為其 glob 比對是非遞迴的。除非傳入 `&scope=docs|all`，否則 `/memory/search` 會略過文件，因此交接文本絕不會淹沒事實查詢。

兩個命名空間在 GET、PUT 和 DELETE 上皆支援 `?section=<name>`，用於定位單一 `## ` 區塊：從 20 KB 的檔案中讀取三行，或將三行接合回去而不更動任何其他位元組。鎖定單位仍是整個檔案 —— `If-Match` 依舊攜帶整檔的 ETag —— 僅有*編輯*單位變成了區段（section）。這對 LLM 呼叫端至關重要，否則它們為了修改一行就得載入整個分類，並手動建構整檔修補檔（patch）寫回。若請求本體的標題與區段不符，會回傳 `400`，絕不進行隱式重新命名，因為靜默重新命名會破壞所有指向舊名稱的現有參照。

## UI 的功能

- **側邊欄樹狀圖** —— 儲存結構是扁平的（名稱符合 `^[a-z0-9-]+$`），但命名慣例為 `<parent>-<sub>`，因此層級是透過最長前綴比對還原：`infra-pc-tuning` 會巢狀收合在 `infra-pc` 下，而非 `infra`。折疊狀態會被保留；過濾與導覽會強制展開祖先節點而不會覆寫該狀態。
- **閱讀檢視** —— 算繪後的 Markdown，具備區段大綱，並透過 `<!-- verified: YYYY-MM-DD -->` 標記驅動時效性徽章。
- **編輯器** —— 具備捲動同步的即時預覽。透過隱藏的鏡像元素測量每個自動折行（soft-wrapped）原始碼行的實際位置，並固定兩端的捲動極限，因此即使算繪區塊與原始碼行的高度不同，窗格也能保持對齊。
- **並行控制** —— 儲存時會攜帶載入文件時的 ETag。若發生 `409` 會開啟差異比較（diff），提供*載入對方的版本*、*以我的版本覆寫*或*繼續編輯*等選項。絕不會有任何內容被靜默覆蓋。
- **草稿** —— 輸入時文字會即時鏡像至 `localStorage`，因此關閉分頁也不會遺失內容。
- **歷史紀錄** —— git 修訂版本、單一修訂檢視、與目前版本比較差異，以及作為前向 commit 進行還原（絕不重寫歷史）。
- **搜尋** —— 跨整個語料庫搜尋，並支援跳轉至指定行。

## 驗證機制

入口有兩種，兩者刻意不對稱。

**Agent** 繼續使用 Bearer Token —— 保持不變，且永遠不會被要求第二因子。持有 Token 者本來就能透過 API 讀寫整個儲存區，因此在瀏覽器這道門加上第二因子並不會守住任何東西。

**人** 使用 Google 登入，讓手機不必持有 Token 也能讀取儲存區。第二因子就是 Google 帳號本身已有的那一個；授權判斷則來自 `auth.json` 裡的電子郵件允許清單，因為「用 Google 登入了」本身只證明對方擁有一個 Google 帳號。`GET /auth/google` 會啟動帶 PKCE 的 authorization-code 交握，callback 則透過直連 Google 的後端通道交換授權碼。這也是此處不驗證 ID token 簽章、且整個流程不需要任何新依賴的原因：本服務與 Google token endpoint 之間沒有任何中介，而這正是 JWT 驗簽所要建立的性質。

兩條路徑最終都通往同一個 Cookie。以 Token 執行 `POST /auth/login` 依然可用，並且是 Google 無法連線、允許清單設錯、或手邊沒有瀏覽器可跑同意畫面時的退路。

該 Cookie 為 HttpOnly，並以 API Token 衍生的金鑰簽署，因此輪替 Token 會將所有瀏覽器登出，且無需管理第二個密鑰。`auth.json` 中的 `keyver` 是同一個開關，但不必動到 Token：將它加一，所有瀏覽器工作階段立即失效，而所有 Agent 完全不受影響（`manage_auth.py sign-out-everyone`）。

### 設定 Google 登入

在 <https://console.cloud.google.com/apis/credentials> 建立一組 OAuth **Web application** 用戶端，授權重新導向 URI 設為 `https://<你的主機>/auth/google/callback`，然後在機器上執行：

```bash
sudo -u claudemem $APP_DIR/venv/bin/python $APP_DIR/manage_auth.py \
     setup <client-id> https://<你的主機>/auth/google/callback you@example.com
```

它會在終端機提示輸入 client secret，而不是從 `argv` 讀取，並將 `auth.json` 以 600 權限寫在 `main.py` 旁邊 —— 絕不放進 `data/`，那是一個會永久保留每個檔案每一版的 git repo。不需要重啟：該檔案內容變動時會自動重新讀取。

不設定 Google 時，服務的行為與先前完全相同 —— 登入頁提供 Token 欄位，`/auth/google` 回應 503。

透過 Cookie 授權的寫入請求還必須發送 `X-Memory-Actor`；跨站請求無法設定自訂標頭，此外 Cookie 還設有 `SameSite=strict`。該標頭同時兼作 git commit 中的作者（`PUT infra via memory-web`）。

登入設有依客戶端 IP 的速率限制。FastAPI 內建的 `/docs`、`/redoc` 與 `/openapi.json` 皆已停用 —— 在公開主機名稱上，結構定義（schema）是唯一無需驗證即可讀取的內容，且 `/docs` 現已作為上述的工作文件命名空間。

## 檔案結構

| Path | Deployed to | What |
|---|---|---|
| `main.py` | `$APP_DIR/main.py` | API，加上 `/auth/*` 與靜態掛載 |
| `webauth.py` | `$APP_DIR/webauth.py` | HMAC Cookie 工作階段 + 登入速率限制 |
| `manage_auth.py` | `$APP_DIR/manage_auth.py` | 管理 `auth.json`：Google 用戶端、允許清單、`keyver` |
| `web/` | `$APP_DIR/web/` | `index.html`、`app.css`、`app.js`、`md.js`、`diff.js` |
| `test-web.sh` | `$APP_DIR/test-web.sh` | 伺服器測試套件，於主機上執行 |
| `memapi.py` | 用戶端任意位置 | 此 API 的命令列用戶端 |
| `devstub.py` | — | 本地 UI 開發用的假後端，僅限開發使用 |
| `rendertest.js` | — | 針對 `md.js` / `diff.js` 的 28 項檢查，僅限開發使用 |
| `fixtures/` | — | 算繪測試所執行的合成語料庫 |

## 開發

```bash
python devstub.py     # serves web/ on :8123 with a fake API, no token needed
node rendertest.js    # markdown + diff checks
```

`devstub.py` 從記憶體中的測試資料模擬整個 API，包含一個寫入永遠回傳 `409` 的分類，以便在沒有伺服器的情況下測試衝突處理 UI。

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

發布 JS 或 CSS 時，請遞增 `index.html` 中 `<script>`/`<link>` 標籤上的 `?v=` 查詢參數，否則瀏覽器會繼續使用舊的快取複本。

## 備註

- 靜態掛載必須保持為 `main.py` 中的**最後一條**陳述式。Starlette 依宣告順序比對路由；若過早加入掛載於 `/` 的路由，將會吞沒 `/memory/*`。
- `md.js` 是特意設計的子集算繪器，而非完整的 Markdown 函式庫：它會先跳脫所有內容以確保筆記不會變成可執行的 HTML、不支援 `_underscore_` 強調語法（語料庫中充斥著 `snake_case` 識別碼），並將 `<!-- verified: DATE -->` 轉換為時效性徽章而非直接丟棄。
- `test-web.sh` 在執行前會重新啟動服務，使記憶體中的登入速率限制計數器歸零；速率限制測試排在最後，因為它會耗盡該時間視窗的額度。

## 授權條款

MIT。
