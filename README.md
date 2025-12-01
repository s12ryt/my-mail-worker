# my-mail-worker
這算是我無聊搞得東西
使用google gemini 3 pro生成
第一步：獲取 Cloudflare API Token
GitHub 需要權限才能幫你操作 Cloudflare。

登錄 Cloudflare Dashboard。
點擊右上角頭像 -> My Profile -> API Tokens。
點擊 Create Token。
使用模板：選擇 Edit Cloudflare Workers 模板。
權限保持默認，點擊 Continue to summary -> Create Token。
複製這個 Token (只會顯示一次)。
同時，回到 Worker 首頁，在右側邊欄找到 Account ID，也複製下來。
第二步：在 GitHub 添加 Secrets
進入你的 GitHub 倉庫 (my-mail-worker)。
點擊上方 Settings -> 左側邊欄 Secrets and variables -> Actions。
點擊 New repository secret，依序添加以下變數：
Secret Name (名稱)	Value (值)	說明
CLOUDFLARE_API_TOKEN	(剛複製的 API Token)	用於授權部署
CLOUDFLARE_ACCOUNT_ID	(剛複製的 Account ID)	你的帳戶 ID
JWT_SECRET	(你的亂碼密鑰)	用於加密 Token
SALT	(你的亂碼鹽)	用於加密密碼
EMAIL_DOMAIN	xn--doqx38lgecsvq.netlib.re	你的郵件域名
TG_BOT_TOKEN	(你的 TG Token)	(可選)
TG_CHAT_ID	(你的 TG ID)	(可選)
