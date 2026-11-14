[English](README.md) · **繁體中文**

# claude-memory-web

專為 Claude 設計的個人長期記憶庫 —— 一個小型的 FastAPI 服務，用於儲存分類的 Markdown 筆記，每次寫入都會 git commit，並在 `/mcp` 作為 [MCP 伺服器](#連接-claude-mcp) 提供給 Claude，讓所有 Claude 工作階段（任何機器上的 Claude Code、claude.ai、Claude 應用程式）都能讀寫同一份記憶。同一個應用程式也在 `/` 為使用者提供瀏覽器 UI，因此沒有 CORS 問題、不需要第二台主機，也無需任何建置步驟。

原生 JavaScript（Vanilla JS）、無 npm、無 CDN、無建置步驟。伺服器需要四個 Python 套件（`requirements.txt`）。它在 Raspberry Pi 4 上執行。

![no build step](https://img.shields.io/badge/build-none-informational)

## 快速總覽

- 一個 FastAPI 服務：REST API、`/mcp` MCP 伺服器，以及 `/` 的瀏覽器 UI。
- 十二個 MCP 工具，透過 Streamable HTTP、無狀態、純 JSON 提供；用戶端無需安裝任何東西。
- 事實存放在 `/memory/{category}`，工作文件在 `/docs/{slug}`，可重用的程序在 `/skills/{domain}`。
- 每次寫入都是一次 git commit；`?section=<name>` 編輯單一 `## ` 區塊，`&mode=rank` 以 BM25 排序區段。
- Agent 使用 bearer `mem_` 金鑰或 OAuth 授權；使用者使用 GitHub、Google 或 passkey。
- 無建置步驟、四個 Python 套件、一台 Raspberry Pi 4。

## 連接 Claude (MCP)

`POST /mcp` 是一個 Model Context Protocol 伺服器（Streamable HTTP、無狀態、純 JSON 回應），對外提供十二個工具：`memory_list`、`memory_index`、`memory_search`、`memory_get`、`memory_write`、`memory_edit`、`memory_delete`、`memory_history`、`memory_pins`、`memory_recent`、`memory_issue_pass`、`memory_revoke_pass`。這就是 Claude 存取儲存庫的方式；不用裝用戶端，用戶端也不用管任何更新，因為所有工具及其說明皆由伺服器提供。

- **claude.ai / Claude 應用程式**：Settings → Connectors → Add custom connector，URL 填入 `https://<host>/mcp`。Claude 會自己註冊（RFC 7591），把你導向到 `/oauth/authorize`，以 Google/GitHub 登入後按下 Allow。該連線會列在 UI 的 MCP 頁面（`/#/keys`）中的 *Connected apps* 底下，也可以在這裡中斷連線。
- **Claude Code**：在 MCP 頁面簽發一把金鑰，頁面會直接提供組好的指令：

  ```bash
  claude mcp add --transport http --scope user memory https://<host>/mcp \
    --header "Authorization: Bearer <mem_ key>"
  ```

  不加 `--header` 的話，會改走 loopback 重新導向，做同樣的 OAuth 登入。

每個工具都在同一個行程內呼叫底層的 [REST 路由](#此-api-是什麼)，所以 ETag 前置條件、roster 檢查機制和 git commit 全都照樣適用。寫入時需要帶入 `memory_get` 回傳的 `etag`；沒有任何用戶端快取可以依賴。

`mcpoauth.py` 是 `/mcp` 的 OAuth 2.1 授權伺服器；access token 效期為一小時，且絕不被 REST API 接受。註冊、PKCE、refresh token 與授權記錄檔的完整規則請見 [驗證與存取](docs/auth.zh-TW.md#mcp-oauth)。

## UI 的功能

- **側邊欄樹狀圖** —— 儲存結構是扁平的（名稱符合 `^[a-z0-9-]+$`），但命名慣例為 `<parent>-<sub>`，所以層級靠最長前綴比對還原：`infra-pc-tuning` 會巢狀收合在 `infra-pc` 下，而非 `infra`。折疊狀態會被保留；過濾與導覽會強制展開祖先節點而不會覆寫該狀態。
- **閱讀檢視** —— 算繪後的 Markdown，具備區段大綱，並用 `<!-- verified: YYYY-MM-DD -->` 標記決定時效性徽章。
- **編輯器** —— 具備捲動同步的即時預覽。用隱藏的鏡像元素量出每個自動折行（soft-wrapped）原始碼行的實際位置，並固定兩端的捲動極限，因此即使算繪區塊與原始碼行的高度不同，窗格也能保持對齊。
- **並行控制** —— 儲存時會攜帶載入文件時的 ETag。若發生 `409` 會開啟差異比較（diff），提供*載入對方的版本*、*以我的版本覆寫*或*繼續編輯*等選項。絕不會有任何內容被靜默覆蓋。
- **草稿** —— 輸入時文字會即時鏡像至 `localStorage`，因此關閉分頁也不會遺失內容。
- **歷史紀錄** —— git 修訂版本、單一修訂檢視、與目前版本比較差異，以及還原（做成一個往前的新 commit，絕不重寫歷史）。
- **搜尋** —— 跨整個語料庫搜尋，並支援跳轉至指定行。
- **MCP 頁面** —— 說明如何連接 claude.ai 與 Claude Code、簽發與刪除金鑰（每把新金鑰皆附帶其 `claude mcp add` 指令），以及已連線應用程式清單與中斷連線按鈕。

## 此 API 是什麼

在 MCP 工具與瀏覽器 UI 底層的是同一個 REST API。它為每個分類儲存一個 Markdown 檔案，每次寫入都會 git commit，並用 `If-Match` ETag（本體的 git blob SHA）把關每次寫入。

[API 參考](docs/api.zh-TW.md)

## 驗證機制

Agent 提供 bearer 憑證 —— `mem_` 金鑰或 OAuth 授權 —— 永遠不會被要求第二因子。使用者以 GitHub 或 Google 登入，比對 `auth.json` 中的允許清單，或以 passkey 登入；所有入口最終都取得同一個 HttpOnly Cookie。具名的 bearer 金鑰可逐一撤銷。

[驗證與存取](docs/auth.zh-TW.md)

## 執行與部署

無需打包步驟：scp 後重新啟動即可。單一程式碼目錄可以服務多個完全獨立的儲存庫，每個由環境變數命名；設定 `MEMORY_MCP_UPSTREAM` 後，`/mcp` 會變成帶驗證的 proxy。

[營運與部署](docs/operations.zh-TW.md)

## 開發

`devstub.py` 以假 API 在 `:8123` 上提供 `web/`，`rendertest.js` 對 `md.js` / `diff.js` 執行 28 項檢查。`tests/` 包含離線單元測試，以及連接器與 passkey 的實機流程。

[開發](docs/development.zh-TW.md)

## 文件

| 主題 | English | 繁體中文 |
|---|---|---|
| REST API、命名空間、搜尋 | [docs/api.md](docs/api.md) | [docs/api.zh-TW.md](docs/api.zh-TW.md) |
| 驗證、金鑰、passkey、提供者 | [docs/auth.md](docs/auth.md) | [docs/auth.zh-TW.md](docs/auth.zh-TW.md) |
| 部署、多執行個體、轉送 | [docs/operations.md](docs/operations.md) | [docs/operations.zh-TW.md](docs/operations.zh-TW.md) |
| 檔案、開發、備註 | [docs/development.md](docs/development.md) | [docs/development.zh-TW.md](docs/development.zh-TW.md) |

## 授權條款

MIT。
