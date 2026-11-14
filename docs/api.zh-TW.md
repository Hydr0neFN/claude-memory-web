# API

[← README](../README.md) · [English](api.md) · [繁體中文](api.zh-TW.md)

在 MCP 工具與瀏覽器 UI 底層的是同一個 REST API；兩者都呼叫它，且兩者都不重新實作其任何規則。它為每個分類儲存一個 Markdown 檔案，由單一 bearer token 保護，並在每次寫入時進行 git commit，確保任何編輯皆可復原。讀取為 `GET /memory/{category}`；寫入需要帶有先前讀取到的 ETag 的 `If-Match`，該 ETag 即為本體的 git blob SHA。這裡的 `main.py` 與 `webauth.py` 即構成了整個伺服器。

該 ETag 是**磁碟上**位元組的 blob SHA，且每個讀取路徑 —— 分類、文件以及兩種索引列表 —— 都以與寫入防護相同的方式計算它。搞錯這點會引發難以察覺且棘手的問題：如果改為雜湊**解碼後的**文字，通用換行符號（universal-newline）轉換就會介入，導致以 CRLF 儲存的檔案以 LF 形式提供，並依據 LF 形式計算雜湊。如此一來，如實回傳所接收 ETag 的用戶端將永遠被以 `409 etag mismatch` 拒絕，即使根本沒有任何並行寫入者也是如此。因此，請求本體會正規化為 LF，且必須是有效的 UTF-8，否則寫入將被拒絕並回傳 `400` —— 若沒有這項檢查，一個損壞的本體就會破壞整個儲存庫的 `index`、`search` 和 `pins`，因為這三者都會讀取所有檔案。`tests/test_etag_crlf.py` 確保了這項約定。

系統共有三個命名空間。`/memory/{category}` 存放事實（facts）—— 簡短、去重複、單一主題。`/docs/{slug}` 存放工作文件 —— 交接紀錄（handoffs）、操作手冊（runbooks）、稽核報告：篇幅長、專案範圍、採取代換而非累加。文件存放在 `data/docs/` 中，所有 `/memory` 端點都看不到它們，因為其 glob 比對是非遞迴的。除非傳入 `&scope=docs|all`，否則 `/memory/search` 會略過文件，因此交接文本絕不會淹沒事實查詢。

第三個命名空間 `/skills/{domain}` 存放可重用的程序：每個 domain 一個 `data/skills/<domain>.md` 檔案，每項技能一個 `## msk-<12 hex> <title>` 區段。區段以 id 定位（`?section=msk-<id>`），因此重新命名技能不會破壞呼叫端。`GET /skills/index` 列出解析後的中繼資料（狀態、refs、uses、last use），`GET /skills/backlinks?ref=<category>` 找出參照某個分類或其任一區段的技能；兩者皆由檔案計算而得，絕不依賴第二份索引。`&scope=skills|all` 會將技能加入搜尋，而 MCP 在可接受 memory 或 docs 的地方也接受 `namespace="skills"`。

搜尋預設回傳包含所有詞彙的每一行。`&mode=rank` 則以 BM25 對整個區段排序（OR 語意、輕度詞幹化、CJK 雙字詞；見純 Python 的 `searchrank.py`），因此文本恰好沒用到的某個詞不再讓結果歸零，且每筆結果都會列出它 `matched` 的詞。索引由 Markdown 衍生，檔案變動時重建。稠密向量（dense embeddings）曾評估後暫緩：在共用的 Pi 上多掛約 150 MB 的執行環境，對一個約 1 MB、且讀者能自行改寫查詢的語料庫而言，比 BM25 多得的效益很少。

兩個命名空間在 GET、PUT 和 DELETE 上皆支援 `?section=<name>`，用於定位單一 `## ` 區塊：從 20 KB 的檔案中讀取三行，或將三行接合回去而不更動任何其他位元組。鎖定單位仍是整個檔案 —— `If-Match` 依舊攜帶整檔的 ETag —— 僅有*編輯*單位變成了區段（section）。這對 LLM 呼叫端至關重要，否則它們為了修改一行就得載入整個分類，並手動建構整檔修補檔（patch）寫回。若請求本體的標題與區段不符，會回傳 `400`，絕不進行隱式重新命名，因為靜默重新命名會破壞所有指向舊名稱的現有參照。
