# 驗證與存取

[← README](../README.md) · [English](auth.md) · [繁體中文](auth.zh-TW.md)

入口有兩種，兩者刻意不對稱。

**Agent** —— 透過 MCP 連線的 Claude —— 提供 bearer 憑證：一把 `mem_` 金鑰或來自連接器（connector）流程的 OAuth 授權，永遠不會被要求第二因子。持有者本來就能讀寫整個儲存庫，因此在瀏覽器這道門加第二因子也擋不住什麼。

**使用者** 使用 GitHub 或 Google 登入，讓手機不用持有 token 也能讀取儲存庫。第二因子就是該帳號本來就有的保護；`auth.json` 中的電子郵件允許清單則是授權步驟，因為單純「使用 GitHub 登入」只代表對方擁有任何一個 GitHub 帳號。`GET /auth/<provider>` 會啟動授權碼（authorization-code）交握，回呼（callback）則透過直接對提供者發起的後端通道呼叫交換授權碼。這也是此處不驗證 token 簽章、且整個流程無需加入任何相依套件的原因：本服務與提供者的 token 端點之間沒有任何中介，而 JWT 驗證要確認的正是這一點。

兩個提供者都可以設定，也可以只設定其中一個；沒設定或允許清單是空的提供者就是關閉的，其按鈕會被隱藏，且路由會回應 503。兩者之間有兩項實質上的差異：**GitHub OAuth App 會忽略 PKCE**，因此 `code_challenge` 僅傳送給 Google，GitHub 的交握純粹依賴簽章後的 state cookie 與 client secret 來維繫；且 **GitHub 會將被拒絕的 code 交換回傳為帶有 `error` 本體的 HTTP 200**，因此無法利用狀態行來區分成功或失敗。GitHub 的身分識別來自 `GET /user/emails`（回傳帳號上的所有電子郵件地址），因此允許清單比對的是已驗證的地址。

**或以 passkey 登入**，前提是已註冊一把：使用手機本身的指紋或 PIN，整個流程完全沒有第三方。參見 [Passkeys](#passkeys)。

所有這些路徑最終都會取得同一個 Cookie。帶有 token 的 `POST /auth/login` 依然可用，且在 Google 無法連線、允許清單錯誤或沒有瀏覽器可執行同意畫面時，是重新取回存取權的後路。

該 Cookie 具備 HttpOnly，並用從 API token 衍生的金鑰簽章，所以輪替 token 會讓所有瀏覽器登出，也不用管理第二把密鑰。`auth.json` 中的 `keyver` 是不更動 token 時的同等機制：遞增它即可讓所有瀏覽器工作階段失效，同時讓所有 agent 繼續正常運作（`manage_auth.py sign-out-everyone`）。

## 金鑰

已登入的瀏覽器可在 MCP 頁面（`/#/keys`）簽發具名的 bearer 金鑰 —— 一台裝置或一個 agent 一把。金鑰的讀寫權限與 master token 完全相同，但刪除它不會影響其他任何東西，所以手機弄丟時，只要單獨撤銷這把金鑰，不用輪替 token，也不用把所有瀏覽器與 agent 一起強制登出。

金鑰也可以簽發成 `"scope": "skills-writer"`，預設則是 `"all"`：它可讀取 `/memory` 並讀寫 `/skills`，其他一概不行（不可刪除、不可用 `/docs`、`/mcp` 或金鑰管理）。在 scope 存在之前寫入的記錄一律視為 `all`。

金鑰無法簽發或刪除金鑰。該操作僅限 Cookie，因此外洩的金鑰無法自行簽發出比它自身撤銷後還活得更久的接班金鑰。秘密僅顯示一次且絕不儲存 —— `apikeys.json`（權限 600，位於 `main.py` 旁，絕不放入 `data/` 內）只存放其 SHA-256。256 位元的 `secrets.token_urlsafe` 不需要慢速 KDF；沒有任何暴力破解的空間。

Claude Code 就是把金鑰放進 `Authorization: Bearer <key>` 送到 `/mcp`；頁面會在新的密鑰旁顯示現成的 `claude mcp add` 指令。

## Passkeys

passkey 是一組由手機或筆電持有、且只有在指紋、臉部或 PIN 驗證後才會用於此網站的密鑰對。服務只儲存公開的那一半，其他什麼都不存 —— `passkeys.json`（權限 600，位於 `main.py` 旁，絕不放入 `data/` 內）—— 因此機器上沒有值得竊取的東西，也沒有第二個密鑰需要備份。以 passkey 登入最終取得與其他登入方式相同的 `mem_session` Cookie，且 `/auth/me` 會回報 `"via": "passkey"`。

將 `MEMORY_RP_ID` 設為公開主機名稱（或設定 `MEMORY_PUBLIC_URL` 讓它推導）並重新啟動；登入頁面就會提供此選項。兩者皆未設定時，passkey 即為關閉：所有 passkey 路由回應 503，且 `/auth/me` 顯示 `"passkey": false`。信賴憑證方（relying-party）id 與 origin 來自設定，絕不來自 `Host` 標頭 —— 否則以另一個名稱代理此頁面的網站，其自身 origin 就會被接受。

| 路由 | 誰可呼叫 |
|---|---|
| `POST /auth/passkey/register/options`, `…/register/verify` | 已登入的瀏覽器（Cookie + `X-Memory-Actor`），且其登入時間在 15 分鐘內 |
| `POST /auth/passkey/login/options`, `…/login/verify` | 任何人；每個用戶端每 5 分鐘 5 次登入失敗後，兩者皆回應 429 |
| `GET /auth/passkeys`, `DELETE /auth/passkeys/{id}` | 已登入的瀏覽器（Cookie + `X-Memory-Actor`） |

註冊需要近期的登入，原因與簽發金鑰相同：passkey 的壽命長於建立它的工作階段，因此一個已登入一週的分頁中的腳本無法悄悄新增一把。bearer 憑證永遠無法註冊 passkey。刪除則不需要近期登入 —— 剛遺失手機的人不應先被迫尋找其他登入方式。

簡言之，檢查的項目包括：挑戰（challenge）是發給此瀏覽器（一份簽章過的 HttpOnly Cookie）、用於此次儀式、且在 5 分鐘內，並在第一次嘗試時即消耗，無論成功與否；origin 與 RP id 的雜湊完全相符；驗證器表示使用者有出席*且*已驗證；對 `authenticatorData || SHA-256(clientDataJSON)` 的簽章能以儲存的金鑰驗證（ES256、RS256 或 Ed25519，金鑰的類型與大小固定對應至該演算法）；且計數器必須向前推進，除非驗證器不維護計數。`userHandle` 會被忽略。被拒絕的登入無論原因為何，都只回傳一種狀態與一種本體，因此此路由無法用來得知哪些憑證存在，而登入選項也從不指名任何一把。

最多 10 把 passkey。`keyver`（sign-out-everyone）會終止每一個 passkey *工作階段*，但保留已註冊的 passkey，因此擁有者可以直接重新登入 —— 這也意味著他人註冊的 passkey 會存活下來；請檢查清單。在主機上：

```bash
sudo -u claudemem $APP_DIR/venv/bin/python $APP_DIR/manage_auth.py passkeys
sudo -u claudemem $APP_DIR/venv/bin/python $APP_DIR/manage_auth.py passkey-delete <id>
```

損壞的 `passkeys.json` 會被視為空：passkey 登入會安全地失敗（fail closed），token 與所有 bearer 憑證仍可正常運作，且在修復之前不會有任何東西覆寫該檔案。與 `auth.json` 一樣，它會在位元組內容變更時重新讀取。

## 設定提供者

GitHub 的部分，請在 <https://github.com/settings/developers> 註冊一個 OAuth App，授權回呼 URL 填寫 `https://<your host>/auth/github/callback`；client id 與 secret 會立即發放。Google 的部分，請在 <https://console.cloud.google.com/apis/credentials> 建立一個 OAuth **Web application** 用戶端，重新導向 URI 填寫 `https://<your host>/auth/google/callback`（此項需先填寫同意畫面表單）。接著在主機上執行：

```bash
sudo -u claudemem $APP_DIR/venv/bin/python $APP_DIR/manage_auth.py \
     setup github <client-id> https://<your host>/auth/github/callback you@example.com
```

允許清單上的地址必須是提供者會回報為已驗證的地址 —— 以 GitHub 來說，就是必須是 <https://github.com/settings/emails> 上的地址，而非 `users.noreply.github.com` 別名。

指令會在終端機上提示輸入 client secret，不從 `argv` 接收，並將 `auth.json` 以權限 600 寫入 `main.py` 旁 —— 絕不放在 `data/` 內，因為後者是一個會永久保留其中每個檔案所有版本的 git 儲存庫。無需重新啟動：檔案內容變更時會自動重新讀取。

若完全不設定任何提供者，服務的行為將與以往完全相同 —— 登入頁面會提供 token 欄位，且 `/auth/<provider>` 會回應 503。

用 Cookie 授權的寫入還必須帶上 `X-Memory-Actor`；跨站請求無法設定自訂標頭，且該 Cookie 還額外設定了 `SameSite=strict`。此標頭同時兼作 git commit 中的作者（`PUT infra via memory-web`）。

登入會依用戶端 IP 限速。FastAPI 內建的 `/docs`、`/redoc` 與 `/openapi.json` 皆已停用 —— 在公開主機名稱上，結構定義（schema）是唯一無需驗證即可讀取的內容，且 `/docs` 現已作為前述的工作文件命名空間。

## MCP OAuth

`mcpoauth.py` 為授權伺服器。依規範要求開放註冊，但授權碼僅會在已登入的擁有者按下 Allow 後，才重新導向至 Claude 自身的 callback 或 loopback URI，且僅限持有 PKCE verifier 的請求者。Access token 效期為一小時，且僅被 `/mcp` 接受 —— 絕不被 REST API 接受。Refresh token 效期為自上次使用起 90 天且不輪替（請參閱該模組的 docstring）。授權記錄存於 `mcpoauth.json`（權限 600，僅存雜湊值）。若 Host 標頭不再是公開名稱，請設定 `MEMORY_PUBLIC_URL`。
