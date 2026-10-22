import os, secrets, hashlib, base64, time, json
from urllib.parse import urlencode
import httpx
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware

BASE_DEFAULT = "https://sennin-account-api.xianrendesu.workers.dev"
app = FastAPI(title="Sennin OAuth Tester")
app.add_middleware(SessionMiddleware, secret_key=os.environ.get("SESSION_SECRET", secrets.token_urlsafe(48)), same_site="lax")
DB = {}

def store(req):
    sid = req.session.get("sid")
    if not sid:
        sid = secrets.token_urlsafe(32)
        req.session["sid"] = sid
    return DB.setdefault(sid, {"cfg": {}, "oauth": None, "tokens": None, "result": None, "logs": []})

def safe_base(value):
    value = (value or BASE_DEFAULT).strip().rstrip("/")
    if not (value.startswith("https://") or value.startswith("http://localhost") or value.startswith("http://127.0.0.1")):
        raise ValueError("Base URLはHTTPS、またはlocalhostにしてください")
    return value

def log(st, method, url, status=None, request_data=None, response_data=None):
    st["logs"].insert(0, {"time": time.strftime("%H:%M:%S"), "method": method, "url": url, "status": status, "request": request_data or {}, "response": response_data})
    st["logs"] = st["logs"][:30]

def render(req, body, msg=""):
    notice = f'<p class="notice">{msg}</p>' if msg else ""
    return HTMLResponse(f'''<!doctype html><html lang="ja"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sennin OAuth Tester</title>
<style>
*{{box-sizing:border-box}}body{{margin:0;background:#0b1020;color:#eef2ff;font:15px/1.5 system-ui,sans-serif}}main{{max-width:1000px;margin:auto;padding:22px 14px 50px}}h1{{font-size:30px;margin:0}}h2{{font-size:18px;margin:0 0 12px}}p,small{{color:#a7b2cc}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,390px),1fr));gap:14px}}.card{{background:#141b2f;border:1px solid #2a3550;border-radius:16px;padding:16px;margin:0 0 14px}}label{{display:block;color:#a7b2cc;font-size:13px;margin:9px 0 4px}}input{{width:100%;background:#0b1223;color:white;border:1px solid #35425e;border-radius:9px;padding:10px}}button,.btn{{display:inline-block;background:#9df0d0;color:#08151b;border:0;border-radius:9px;padding:10px 13px;font-weight:700;cursor:pointer;margin:7px 5px 0 0;text-decoration:none}}.secondary{{background:#25314b;color:#eef2ff}}.danger{{background:#4a2631;color:#ffd5dc}}.row{{display:grid;grid-template-columns:1fr 1fr;gap:10px}}.scopes{{display:flex;flex-wrap:wrap;gap:12px}}.scopes label{{display:flex;align-items:center;gap:5px;color:#eef2ff}}.scopes input{{width:auto}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;max-height:330px;overflow:auto;background:#080d19;border:1px solid #2a3550;border-radius:9px;padding:10px;font-size:12px}}.notice{{background:#17332d;border:1px solid #37675c;border-radius:10px;padding:12px}}@media(max-width:550px){{.row{{grid-template-columns:1fr}}}}
</style><main><h1>Sennin Account</h1><p>OAuth 2.0 / API テストクライアント · Authorization Code + PKCE S256</p>{notice}{body}</main></html>''')

def config_html(c):
    scopes = c.get("scopes", ["profile", "email"])
    scope_html = "".join(f'<label><input type="checkbox" name="scopes" value="{s}" {"checked" if s in scopes else ""}>{s}</label>' for s in ["profile", "email", "points:read", "points:write"])
    return f'''<section class="card"><h2>1. クライアント設定</h2><p>client_secretはサーバー側だけで扱います。保存済みなら空欄で維持できます。</p><form method="post" action="/config">
<label>Base URL</label><input name="base_url" value="{c.get('base_url', BASE_DEFAULT)}" required>
<div class="row"><div><label>Client ID</label><input name="client_id" value="{c.get('client_id','')}" required></div><div><label>Client Secret</label><input name="client_secret" type="password" autocomplete="new-password" placeholder="sas_..." value=""></div></div>
<label>登録済み Redirect URI</label><input name="redirect_uri" value="{c.get('redirect_uri','http://localhost:8000/callback')}" required>
<label>スコープ</label><div class="scopes">{scope_html}</div><small>redirect_uriは開発者設定と完全一致が必要。points:writeは管理者承認が必要です。</small><br><button>設定を保存</button></form></section>'''

@app.get("/")
async def home(req: Request):
    st = store(req); t = st.get("tokens") or {}
    body = config_html(st["cfg"]) + f'''<div class="grid"><section class="card"><h2>2. OAuth認可</h2><p>state検証とPKCE S256を使用します。</p><form method="post" action="/authorize"><button>認可を開始</button></form><p>{"トークンあり" if t else "未認証"}</p><form method="post" action="/refresh"><button class="secondary">トークン更新</button></form><form method="post" action="/revoke"><button class="danger">トークン失効</button></form></section>
<section class="card"><h2>3. APIテスト</h2><form method="post" action="/userinfo"><button>userinfo / me</button></form><form method="post" action="/points"><button>ポイント残高</button></form><hr><h2>ポイント調整</h2><p>実際のポイントを変更します。テスト用アカウントでのみ実行してください。</p><form method="post" action="/adjust"><label>amount（負数で減算）</label><input name="amount" type="number" value="1" required><label>reason</label><input name="reason" value="OAuth API テスト" maxlength="100" required><label>idempotency_key（再送時は同じキー）</label><input name="key" value="test-{secrets.token_hex(8)}" required><button>調整を実行</button></form></section></div>
<section class="card"><h2>最新の結果</h2><pre>{json.dumps(st.get("result"), ensure_ascii=False, indent=2) if st.get("result") is not None else "まだAPIを呼び出していません"}</pre></section><section class="card"><h2>操作ログ（トークン等は非記録）</h2><pre>{json.dumps(st["logs"], ensure_ascii=False, indent=2)}</pre><form method="post" action="/clear"><button class="secondary">ログ消去</button></form></section><small>開発用。localhostで使用してください。トークンはメモリ保存で、再起動すると消えます。</small>'''
    return render(req, body)

@app.post("/config")
async def config(req: Request, base_url: str = Form(...), client_id: str = Form(...), client_secret: str = Form(""), redirect_uri: str = Form(...), scopes: list[str] = Form([])):
    st = store(req)
    try:
        base = safe_base(base_url)
        if not (redirect_uri.startswith("https://") or redirect_uri.startswith("http://localhost") or redirect_uri.startswith("http://127.0.0.1")):
            raise ValueError("Redirect URIはHTTPSまたはlocalhostにしてください")
        st["cfg"] = {"base_url": base, "client_id": client_id.strip(), "client_secret": client_secret.strip() or st["cfg"].get("client_secret", ""), "redirect_uri": redirect_uri.strip(), "scopes": [s for s in scopes if s in ["profile", "email", "points:read", "points:write"]]}
        return RedirectResponse("/", 303)
    except ValueError as e:
        return render(req, config_html(st["cfg"]), str(e))

@app.post("/authorize")
async def authorize(req: Request):
    st = store(req); c = st["cfg"]
    if not c.get("client_id") or not c.get("redirect_uri"):
        return render(req, config_html(c), "先にクライアント設定を保存してください")
    verifier = secrets.token_urlsafe(48)[:64]
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    state = secrets.token_urlsafe(24)
    st["oauth"] = {"verifier": verifier, "state": state, "time": time.time()}
    params = {"response_type": "code", "client_id": c["client_id"], "redirect_uri": c["redirect_uri"], "scope": " ".join(c.get("scopes") or ["profile"]), "state": state, "code_challenge": challenge, "code_challenge_method": "S256"}
    log(st, "GET", c["base_url"] + "/oauth/authorize", request_data={"scope": params["scope"]})
    return RedirectResponse(c["base_url"] + "/oauth/authorize?" + urlencode(params), 303)

@app.get("/callback")
async def callback(req: Request, code: str = "", state: str = "", error: str = "", error_description: str = ""):
    st = store(req); c = st["cfg"]; o = st.get("oauth") or {}
    if error:
        st["result"] = {"error": error, "error_description": error_description}
        return render(req, '<section class="card"><h2>認可エラー</h2><a class="btn" href="/">戻る</a></section>')
    if not code or not state or not secrets.compare_digest(state, o.get("state", "")) or time.time() - o.get("time", 0) > 600:
        return render(req, '<section class="card"><h2>state検証失敗または期限切れ</h2><a class="btn" href="/">戻る</a></section>')
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.post(c["base_url"] + "/oauth/token", data={"grant_type": "authorization_code", "code": code, "redirect_uri": c["redirect_uri"], "code_verifier": o["verifier"]}, auth=(c["client_id"], c.get("client_secret", "")))
        data = r.json()
        log(st, "POST", c["base_url"] + "/oauth/token", r.status_code, {"grant_type": "authorization_code"}, {"token_response": "[redacted]"} if r.is_success else data)
        st["result"] = {"status": r.status_code, "body": data if not r.is_success else {"token_type": data.get("token_type"), "expires_in": data.get("expires_in"), "scope": data.get("scope"), "tokens": "[保存済み・非表示]"}}
        if r.is_success and data.get("access_token"):
            st["tokens"] = {"access_token": data["access_token"], "refresh_token": data.get("refresh_token"), "expires": time.time() + int(data.get("expires_in", 3600))}
            st["oauth"] = None
            return RedirectResponse("/", 303)
        return render(req, '<section class="card"><h2>トークン交換失敗</h2><a class="btn" href="/">戻る</a></section>')
    except Exception as e:
        st["result"] = {"error": str(e)}
        return RedirectResponse("/", 303)

async def call_api(req, path, method="GET", body=None):
    st = store(req); c = st["cfg"]; t = st.get("tokens") or {}
    if not t.get("access_token"):
        st["result"] = {"error": "先にOAuth認可を実行してください"}
        return RedirectResponse("/", 303)
    url = c["base_url"] + path
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.request(method, url, headers={"Authorization": "Bearer " + t["access_token"], "Accept": "application/json"}, json=body)
        try: data = r.json()
        except Exception: data = {"body": r.text[:2000]}
        st["result"] = {"method": method, "url": url, "status": r.status_code, "body": data}
        log(st, method, url, r.status_code, body or {}, data)
    except Exception as e:
        st["result"] = {"error": str(e)}
    return RedirectResponse("/", 303)

@app.post("/userinfo")
async def userinfo(req: Request): return await call_api(req, "/oauth/userinfo")
@app.post("/points")
async def points(req: Request): return await call_api(req, "/api/v1/points")
@app.post("/adjust")
async def adjust(req: Request, amount: int = Form(...), reason: str = Form(...), key: str = Form(...)):
    if amount == 0 or len(reason) > 100 or not (8 <= len(key) <= 64) or any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:-" for ch in key):
        store(req)["result"] = {"error": "入力不正。amountは0以外、reasonは100文字以内、keyは8〜64文字の英数字/_.:-"}
        return RedirectResponse("/", 303)
    return await call_api(req, "/api/v1/points/adjust", "POST", {"amount": amount, "reason": reason, "idempotency_key": key})

@app.post("/refresh")
async def refresh(req: Request):
    st = store(req); c = st["cfg"]; t = st.get("tokens") or {}
    if not t.get("refresh_token"):
        st["result"] = {"error": "refresh_tokenがありません。認可してください"}
        return RedirectResponse("/", 303)
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.post(c["base_url"] + "/oauth/token", data={"grant_type": "refresh_token", "refresh_token": t["refresh_token"]}, auth=(c["client_id"], c.get("client_secret", "")))
        data = r.json()
        log(st, "POST", c["base_url"] + "/oauth/token", r.status_code, {"grant_type": "refresh_token"}, {"token_response": "[redacted]"} if r.is_success else data)
        st["result"] = {"status": r.status_code, "body": data if not r.is_success else {"expires_in": data.get("expires_in"), "scope": data.get("scope"), "tokens": "[保存済み・非表示]"}}
        if r.is_success and data.get("access_token"):
            st["tokens"] = {"access_token": data["access_token"], "refresh_token": data.get("refresh_token"), "expires": time.time() + int(data.get("expires_in", 3600))}
    except Exception as e: st["result"] = {"error": str(e)}
    return RedirectResponse("/", 303)

@app.post("/revoke")
async def revoke(req: Request):
    st = store(req); c = st["cfg"]; t = st.get("tokens") or {}
    if not t:
        st["result"] = {"error": "トークンがありません"}
        return RedirectResponse("/", 303)
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.post(c["base_url"] + "/oauth/revoke", data={"token": t.get("refresh_token") or t.get("access_token")}, auth=(c["client_id"], c.get("client_secret", "")))
        log(st, "POST", c["base_url"] + "/oauth/revoke", r.status_code, {"token": "[redacted]"}, {"status": r.status_code})
        st["result"] = {"status": r.status_code, "body": "失効リクエストを送信しました"}
    except Exception as e: st["result"] = {"error": str(e)}
    st["tokens"] = None
    return RedirectResponse("/", 303)

@app.post("/clear")
async def clear(req: Request):
    store(req)["logs"] = []
    return RedirectResponse("/", 303)

@app.get("/health")
async def health(): return {"ok": True}
