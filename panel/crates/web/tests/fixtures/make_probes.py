"""Write `probes.json`: the raw HTTP requests `record_goldens.py` sends to the Python panel and
`tests/framework_probes.rs` replays against the Rust one. Placeholders (`{session}`, `{csrf}`,
`{key_admin}`, `{key_monitor}`, `{key_node_sync}`, `{etag_app_js}`, `{last_modified_app_js}`) are
filled in by each runner. Every request carries `Connection: close` (read until EOF)."""
from __future__ import annotations

import base64
import json
from pathlib import Path

H = "Host: testserver\r\nConnection: close\r\n"
S = "Cookie: panel_session={session}; panel_csrf={csrf}\r\nX-CSRF-Token: {csrf}\r\n"
SN = "Cookie: panel_session={session}; panel_csrf={csrf}\r\n"
J = "Content-Type: application/json\r\n"
PROBES: list[dict] = []


def req(method: str, path: str, headers: str = "", body: str | None = None, host: str = H) -> str:
    text = f"{method} {path} HTTP/1.1\r\n{host}{headers}"
    if body is not None:
        text += "Content-Length: {len}\r\n"
    return text + "\r\n"


def add(name: str, request: str, body: str | None = None, body_b64: str | None = None) -> None:
    item = {"name": name, "request": request}
    if body is not None:
        item["body"] = body
        item["request"] = request.replace("{len}", str(len(body.encode())))
    if body_b64 is not None:
        item["body_b64"] = body_b64
        item["request"] = request.replace("{len}", str(len(base64.b64decode(body_b64))))
    PROBES.append(item)


def json_post(name: str, path: str, headers: str, body: str, method: str = "POST") -> None:
    add(name, req(method, path, headers, body), body=body)


# framework basics
add("healthz", req("GET", "/healthz"))
add("healthz_host_port", req("GET", "/healthz", host="Host: testserver:8787\r\nConnection: close\r\n"))
add("healthz_bad_host", req("GET", "/healthz", host="Host: evil.example\r\nConnection: close\r\n"))
add("healthz_host_case", req("GET", "/healthz", host="Host: TestServer\r\nConnection: close\r\n"))
add("healthz_http10_no_host", "GET /healthz HTTP/1.0\r\n\r\n")
add("healthz_www_redirect", req("GET", "/healthz?a=1", host="Host: redirect.example:8080\r\nConnection: close\r\n"))
add("healthz_wildcard_host", req("GET", "/healthz", host="Host: a.wild.example\r\nConnection: close\r\n"))
add("healthz_head_405", req("HEAD", "/healthz"))
add("healthz_post_405", req("POST", "/healthz"))
add("healthz_options_405", req("OPTIONS", "/healthz"))
add("healthz_newline_suffix", req("GET", "/healthz%0A"))
add("healthz_trailing_slash", req("GET", "/healthz/"))
add("unknown_404", req("GET", "/nope"))
add("unknown_404_slash", req("GET", "/nope/"))
add("double_slash", req("GET", "//"))
add("openapi_public_off", req("GET", "/openapi.json"))
add("docs_off", req("GET", "/docs"))
add("keys_trailing_slash", req("GET", "/api/keys/"))
add("keys_trailing_slash_query", req("GET", "/api/keys/?x=1&y=%20"))
add("keys_trailing_slash_quoted", req("GET", "/api/keys%2F"))
add("keys_trailing_slash_odd_chars", req("GET", "/api/keys%20/"))
add("keys_put_405", req("PUT", "/api/keys"))
add("admins_delete_405", req("DELETE", "/api/admins"))
add("admin_id_get_405", req("GET", "/api/admins/1"))
add("keys_enabled_get_405", req("GET", "/api/keys/1/enabled"))
add("reveal_slash_inside", req("GET", "/api/reveal/a%2Fb"))
add("favicon", req("GET", "/favicon.ico"))
add("favicon_head_405", req("HEAD", "/favicon.ico"))
add("index_redirect", req("GET", "/"))
add("index_session", req("GET", "/", SN))
add("login_page", req("GET", "/login"))
add("login_page_session_keeps_csrf", req("GET", "/login", SN))
add("subscription_prefix_csp", req("GET", "/s/"))
add("subscription_prefix_short", req("GET", "/s"))

# the static mount
add("static_bare", req("GET", "/static"))
add("static_dir", req("GET", "/static/"))
add("static_js", req("GET", "/static/app.js"))
add("static_js_head", req("HEAD", "/static/app.js"))
add("static_css", req("GET", "/static/style.css"))
add("static_html", req("GET", "/static/login.html"))
add("static_png", req("GET", "/static/img/logo-64.png"))
add("static_json", req("GET", "/static/i18n/en.json"))
add("static_post_405", req("POST", "/static/app.js"))
add("static_missing", req("GET", "/static/nope.js"))
add("static_escape", req("GET", "/static/../settings.py"))
add("static_escape_quoted", req("GET", "/static/%2e%2e/settings.py"))
add("static_subdir", req("GET", "/static/js"))
add("static_if_none_match", req("GET", "/static/app.js", "If-None-Match: W/\"x\", {etag_app_js}\r\n"))
add("static_if_none_match_weak", req("GET", "/static/app.js", "If-None-Match: W/{etag_app_js}\r\n"))
add("static_if_none_match_miss", req("GET", "/static/app.js", "If-None-Match: \"nope\"\r\n"))
add("static_if_modified_since", req("GET", "/static/app.js", "If-Modified-Since: {last_modified_app_js}\r\n"))
add("static_if_modified_since_old",
    req("GET", "/static/app.js", "If-Modified-Since: Mon, 01 Jan 2001 00:00:00 GMT\r\n"))
add("static_if_modified_since_junk", req("GET", "/static/app.js", "If-Modified-Since: yesterday\r\n"))
add("static_range", req("GET", "/static/app.js", "Range: bytes=0-9\r\n"))
add("static_range_suffix", req("GET", "/static/app.js", "Range: bytes=-5\r\n"))
add("static_range_open", req("GET", "/static/app.js", "Range: bytes=10-\r\n"))
add("static_range_malformed", req("GET", "/static/app.js", "Range: bytes\r\n"))
add("static_range_units", req("GET", "/static/app.js", "Range: items=0-1\r\n"))
add("static_range_empty", req("GET", "/static/app.js", "Range: bytes=x-y\r\n"))
add("static_range_unsatisfiable", req("GET", "/static/app.js", "Range: bytes=99999999-\r\n"))
add("static_range_reversed", req("GET", "/static/app.js", "Range: bytes=9-3\r\n"))
add("static_range_multi", req("GET", "/static/app.js", "Range: bytes=0-4, 10-14, 3-6\r\n"))
add("static_range_if_range_miss", req("GET", "/static/app.js", "Range: bytes=0-9\r\nIf-Range: \"nope\"\r\n"))
add("static_range_if_range_hit", req("GET", "/static/app.js", "Range: bytes=0-9\r\nIf-Range: {etag_app_js}\r\n"))
add("static_range_head", req("HEAD", "/static/app.js", "Range: bytes=0-9\r\n"))

# the body limit
BIG = '{"name":"' + "a" * 70000 + '"}'
json_post("body_too_large_declared", "/api/keys", J, BIG)
CHUNKED = "".join(f"{0x4000:x}\r\n" + "a" * 0x4000 + "\r\n" for _ in range(5)) + "0\r\n\r\n"
add("body_too_large_chunked", f"POST /api/keys HTTP/1.1\r\n{H}{J}Transfer-Encoding: chunked\r\n\r\n", body=CHUNKED)
add("body_chunked_json_invalid", f"POST /api/keys HTTP/1.1\r\n{H}{J}Transfer-Encoding: chunked\r\n\r\n",
    body="7\r\n{bad: 1\r\n0\r\n\r\n")
add("body_limit_on_get", req("GET", "/healthz", "", "x" * 65537), body="x" * 65537)
add("body_at_limit_on_get", req("GET", "/healthz", "", "x" * 65536), body="x" * 65536)

# 422 precedence and request validation
json_post("keys_json_invalid_anon", "/api/keys", J, "{bad")
json_post("keys_valid_json_anon", "/api/keys", J, "{}")
add("keys_no_body_anon", req("POST", "/api/keys"))
json_post("keys_json_invalid_session", "/api/keys", S + J, '{"a": }')
json_post("keys_empty_model_session", "/api/keys", S + J, "{}")
add("keys_no_body_session", req("POST", "/api/keys", S))
json_post("keys_bad_fields_session", "/api/keys", S + J, '{"name":"","scope":"x","expires_at":-1,"extra":1}')
json_post("keys_wrong_types_session", "/api/keys", S + J, '{"name":5,"scope":null,"expires_at":"soon"}')
json_post("keys_array_body_session", "/api/keys", S + J, "[1]")
json_post("keys_null_body_session", "/api/keys", S + J, "null")
json_post("keys_text_plain_session", "/api/keys", S + "Content-Type: text/plain\r\n", '{"name":"t","scope":"admin"}')
json_post("keys_no_content_type_session", "/api/keys", S, '{"name":"t","scope":"admin"}')
json_post("keys_vendor_json_session", "/api/keys", S + "Content-Type: application/vnd.x+json; charset=utf-8\r\n",
          '{"name":5}')
json_post("keys_uppercase_json_type_session", "/api/keys", S + "Content-Type: Application/JSON\r\n", '{"name":5}')
json_post("keys_bad_type_header_session", "/api/keys", S + "Content-Type: json\r\n", '{"name":5}')
add("keys_bad_utf8_session", req("POST", "/api/keys", S + J, "x"),
    body_b64=base64.b64encode(b'{"name":"\xff"}').decode())
json_post("keys_nan_session", "/api/keys", S + J, '{"name":"n","scope":"admin","expires_at":NaN}')
json_post("keys_created_session", "/api/keys", S + J, '{"name":"  probe  ","scope":"monitor","expires_at":null}')
json_post("keys_expired_session", "/api/keys", S + J, '{"name":"old","scope":"monitor","expires_at":5}')
json_post("keys_blank_name_session", "/api/keys", S + J, '{"name":"   ","scope":"monitor"}')
json_post("keys_session_no_csrf", "/api/keys", SN + J, '{"name":"x","scope":"admin"}')
json_post("keys_session_no_csrf_bad_json", "/api/keys", SN + J, "{x")
json_post("keys_monitor_key_forbidden", "/api/keys", "Authorization: Bearer {key_monitor}\r\n" + J, "{}")
json_post("admin_patch_bad_path_and_body", "/api/admins/abc", S + J,
          '{"role":"root","password":"short","active":"maybe","x":1}', method="PATCH")
json_post("admin_patch_missing", "/api/admins/999", S + J, "{}", method="PATCH")
json_post("admin_patch_float_id", "/api/admins/1.0", S + J, "{}", method="PATCH")
json_post("admin_patch_last_owner", "/api/admins/1", S + J, '{"role":"admin"}', method="PATCH")
add("admin_delete_unknown", req("DELETE", "/api/admins/999", S))
add("admin_delete_bad_id", req("DELETE", "/api/admins/x", S))
add("admin_delete_last_owner", req("DELETE", "/api/admins/1", S))
json_post("admin_create_bad", "/api/admins", S + J, '{"username":"bad user","password":"short","role":"god"}')
json_post("admin_create_newline_username", "/api/admins", S + J,
          '{"username":"abc\\n","password":"long enough password","role":"viewer"}')
json_post("admin_create_ok", "/api/admins", S + J,
          '{"username":"probe-viewer","password":"long enough password","role":"viewer"}')
json_post("admin_create_exists", "/api/admins", S + J,
          '{"username":"PROBE-viewer","password":"long enough password","role":"viewer"}')
add("audit_bad_query", req("GET", "/api/audit?limit=0&before_id=x&actor=&action=" + "a" * 129, SN))
add("audit_bad_limit", req("GET", "/api/audit?limit=abc", SN))
add("audit_limit_float", req("GET", "/api/audit?limit=1.0&limit=2&target=nobody", SN))
add("audit_blank_values", req("GET", "/api/audit?limit=&before_id=", SN))
add("audit_anon", req("GET", "/api/audit?limit=0"))
add("me_anon", req("GET", "/api/auth/me"))
add("me_session", req("GET", "/api/auth/me", SN))
add("me_bad_key", req("GET", "/api/auth/me", "Authorization: Bearer pc_nope_x\r\n"))
add("me_bearer_case", req("GET", "/api/auth/me", "Authorization: BEARER   {key_monitor}  \r\n"))
add("me_node_sync_key", req("GET", "/api/auth/me", "Authorization: Bearer {key_node_sync}\r\n"))
add("me_admin_key_over_session", req("GET", "/api/auth/me", SN + "Authorization: Bearer {key_admin}\r\n"))
add("me_basic_auth_falls_to_cookie", req("GET", "/api/auth/me", "Authorization: Basic eDp5\r\n"))
add("logout_no_csrf", req("POST", "/api/auth/logout", SN))
json_post("logout_bad_json_ignored_no_csrf", "/api/auth/logout", SN + J, "{bad")
json_post("login_no_csrf", "/api/auth/login", J, '{"username":"owner","password":"x"}')
json_post("login_bad_model", "/api/auth/login", J, '{"username":"","password":""}')
json_post("login_bad_json", "/api/auth/login", J, '{"username":')
json_post("login_wrong_password", "/api/auth/login", "Cookie: panel_csrf=abc\r\nX-CSRF-Token: abc\r\n" + J,
          '{"username":"owner","password":"wrong-password"}')
add("openapi_session", req("GET", "/api/openapi.json", SN))
add("openapi_monitor_key", req("GET", "/api/openapi.json", "Authorization: Bearer {key_monitor}\r\n"))
add("readiness_session", req("GET", "/api/readiness", SN))
add("readiness_anon", req("GET", "/api/readiness"))
add("admins_list_monitor_key", req("GET", "/api/admins", "Authorization: Bearer {key_monitor}\r\n"))
json_post("keys_enable_bad", "/api/keys/999/enabled", S + J, '{"enabled":"perhaps"}')
json_post("keys_enable_missing", "/api/keys/999/enabled", S + J, '{"enabled":"yes"}')
add("keys_delete_missing", req("DELETE", "/api/keys/999", S))
add("keys_delete_bad_id", req("DELETE", "/api/keys/-x", S))
add("reveal_unknown", req("GET", "/api/reveal/nope", SN))
add("reveal_newline", req("GET", "/api/reveal/abc%0A", SN))
add("forwarded_for_from_unix_peer", req("GET", "/healthz", "X-Forwarded-For: 203.0.113.7\r\nX-Forwarded-Proto: https\r\n"))
add("redirect_ignores_forwarded_proto", req("GET", "/api/keys/", "X-Forwarded-Proto: https\r\n"))
add("quoted_session_cookie", req("GET", "/api/auth/me", "Cookie: junk; panel_session=\"{session}\"\r\n"))


if __name__ == "__main__":
    document = {"allowed_hosts": "testserver,www.redirect.example,*.wild.example", "probes": PROBES}
    (Path(__file__).resolve().parent / "probes.json").write_text(json.dumps(document, indent=1) + "\n")
    print(len(PROBES))
