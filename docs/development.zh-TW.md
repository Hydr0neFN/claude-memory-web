# 開發

[← README](../README.md) · [English](development.md) · [繁體中文](development.zh-TW.md)

## 檔案

| 路徑 | 部署至 | 說明 |
|---|---|---|
| `main.py` | `$APP_DIR/main.py` | API，加上 `/auth/*` 與靜態掛載 |
| `webauth.py` | `$APP_DIR/webauth.py` | HMAC Cookie 工作階段、OAuth 提供者表格、登入速率限制 |
| `manage_auth.py` | `$APP_DIR/manage_auth.py` | 管理 `auth.json`：提供者用戶端、允許清單、`keyver`；列出與刪除 passkey |
| `apikeys.py` | `$APP_DIR/apikeys.py` | 具名稱、可撤銷的 bearer 金鑰，由瀏覽器簽發 |
| `passkeys.py` | `$APP_DIR/passkeys.py` | passkey（WebAuthn）儲存與檢查；唯一需要 `cryptography` 的模組 |
| `requirements.txt` | — | 四個執行階段套件，供 `pip install -r` 使用 |
| `mcpserver.py` | `$APP_DIR/mcpserver.py` | `/mcp`：JSON-RPC 分派與十二個工具 |
| `mcpoauth.py` | `$APP_DIR/mcpoauth.py` | `/mcp` 的 OAuth 2.1 伺服器：註冊、授權碼、授權記錄 |
| `web/` | `$APP_DIR/web/` | `index.html`、`app.css`、`app.js`、`md.js`、`diff.js` |
| `test-web.sh` | `$APP_DIR/test-web.sh` | 伺服器測試套件，於主機上執行 |
| `tests/` | `$APP_DIR/tests/` | 單元測試：`test_webauth.py`（離線）、`test_etag_crlf.py`；`test_passkeys.py`（離線）；`test_mcp_live.py` 針對執行中的應用程式測試完整連接器流程；`test_passkeys_live.py` 以軟體驗證器對 passkey 做同樣的事；`test_isolation_live.py` 驗證兩個執行個體會相互拒絕彼此的憑證 |
| `devstub.py` | — | 本地 UI 開發用的假後端，僅限開發使用 |
| `rendertest.js` | — | 針對 `md.js` / `diff.js` 的 28 項檢查，僅限開發使用 |
| `fixtures/` | — | 算繪測試所執行的合成語料庫 |

## 開發

```bash
python devstub.py     # serves web/ on :8123 with a fake API, no token needed
node rendertest.js    # markdown + diff checks
python tests/test_webauth.py   # sessions, keyver, PKCE state, allowlist; no network
python tests/test_apikeys.py   # minting, verifying, revoking; no network
python tests/test_passkeys.py  # WebAuthn checks, store, challenge cookie; no network
```

`devstub.py` 從記憶體中的測試資料（fixtures）模擬整個 API，包含一個寫入永遠回傳 `409` 的分類，以便在沒有伺服器的情況下測試衝突處理 UI。

放置於最頂層目錄的真實分類會被作為額外的算繪測試輸入，且已被加入 gitignore —— 它們是個人筆記，而非測試資料。

## 備註

- 靜態掛載必須保持為 `main.py` 中的**最後一條**陳述式。Starlette 依宣告順序比對路由；若過早加入掛載於 `/` 的路由，將會吞沒 `/memory/*`。
- `md.js` 是特意設計的子集算繪器，而非完整的 Markdown 函式庫：它會先跳脫所有內容以確保筆記不會變成可執行的 HTML、不支援 `_underscore_` 強調語法（語料庫中充斥著 `snake_case` 識別碼），並將 `<!-- verified: DATE -->` 轉換為時效性徽章而非直接丟棄。
- `test-web.sh` 在執行前會重新啟動服務，使記憶體中的登入速率限制計數器歸零；速率限制測試排在最後，因為它會耗盡該時間視窗的額度。
