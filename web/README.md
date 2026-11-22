# Lattice Admin Console (web/)

Web console for operators/administrators, built against §8 Admin API of the platform API
documentation, plus §12 Plugin hub (third-party plugin distribution for desktop clients,
user-facing `/v1/hub`).

Stack: Vite 5 + React 18 + TypeScript 5 + Ant Design 5 + Axios 1.7.

## Quick start

```cmd
cd web
npm install
npm run dev
```

Serves <http://localhost:5173> by default and proxies `/v1` to `http://127.0.0.1:8080`
(the node's default listen address, see `[http] bind` in `deploy/config/dev.toml`). To
change the target:

```cmd
set VITE_API_TARGET=http://10.0.0.5:8080
npm run dev
```

Production build:

```cmd
npm run build      :: output in web/dist; serve statically (same-origin /v1 proxy required)
```

> The console **has no built-in accounts**: the platform has no self-registration (§2). The
> first administrator is created by node bootstrap (`[admin] bootstrap_username` +
> `bootstrap_password`; dev values in `deploy/config/dev.toml`). After signing in, create
> further accounts under "Users → New account".

## Directory layout

```
web/
├── vite.config.ts          # /v1 proxy
├── src/
│   ├── theme.ts            # design tokens (light/dark antd themes + CSS_VAR colour variables), single source
│   ├── styles.css          # layout skeleton (references CSS variables only, no hard-coded colours)
│   ├── api/
│   │   ├── http.ts         # Axios instance: JWT injection, single-flight 401 refresh, error normalisation, idempotency key
│   │   ├── endpoints.ts    # every §8 endpoint (annotated with its section)
│   │   └── types.ts        # contract types (field names copied from server JSON)
│   ├── auth/
│   │   ├── AuthProvider.tsx  # session, device fingerprint, decoded role
│   │   ├── jwt.ts            # decode JWT payload to read role (§0.2 snapshot)
│   │   └── rbac.ts           # capability matrix (§0.2 table) + role colours/labels
│   ├── components/
│   │   ├── ThemeProvider.tsx # light/dark context: switches antd theme + injects CSS variables + localStorage
│   │   ├── UserAvatar.tsx    # shared avatar (image or initial), same component in account area and user list
│   │   ├── RoleTag.tsx       # shared role badge (admin red / ops gold / user blue)
│   │   ├── StatCard.tsx      # metric card: number + explanation
│   │   ├── HelpTip.tsx       # small question mark for a term
│   │   ├── JsonPeek.tsx      # "Technical details" collapsible block (raw JSON collapsed by default)
│   │   ├── GlossaryDrawer.tsx# guide / glossary (also reachable from the top bar)
│   │   ├── listLayout.ts     # list sizing conventions: fixed height + inner body scroll (LIST_PAGE_SIZE / LIST_SCROLL_Y)
│   │   └── ReasonModal.tsx   # shared dialog for risky actions (reason required)
│   ├── i18n/
│   │   ├── index.tsx         # I18nProvider / useI18n: English source strings + Chinese overlay
│   │   └── locales.zh.ts     # Chinese overlay dictionary (merged from zh.parts)
│   ├── layout/AppLayout.tsx  # grouped navigation + top bar (node status / guide / language switch / theme switch / account menu)
│   ├── lib/
│   │   ├── ulid.ts           # ULID for Idempotency-Key
│   │   ├── useSse.ts         # fetch-based SSE (native EventSource cannot send Authorization)
│   │   ├── labels.ts         # enum-to-copy mappings (status/kind/action/config)
│   │   └── format.ts         # time/bytes/rate/state colours
│   └── pages/                # 17 pages (login + 16 console pages), see the table below
└── README.md
```

## Visual and copy conventions (read before changing the UI)

Three rules are hard constraints; breaking them regresses the console to a state where it
looks unprofessional and the content is hard to understand:

**1. Colours only come from `theme.ts`**

Primary `#2563eb`, sidebar `#0f172a`, content background `#f5f7fa`, cards with a 1px
`#eef1f5` border and a 10px radius. Status colours are semantic only (green = healthy,
red = failed, orange = warning, blue = processing); pages never write
`style={{ color: '#xxx' }}`.

**1.1 Light/dark themes (v0.9)**

- The moon/sun button to the right of "Guide" in the top bar toggles the theme; the login
  page has the same button in its top-right corner. The choice is stored in
  `localStorage['lattice.admin.theme']`; default is light (it does not follow the OS, which
  keeps the visual baseline stable).
- Colours have exactly one source: `lightTheme`/`darkTheme` in `theme.ts` (antd
  `darkAlgorithm`) plus `CSS_VAR` (`--bg-layout`, `--text`, `--card`, ... with values for
  both themes). `ThemeProvider` tags `<html data-theme="light|dark">` and injects `CSS_VAR`
  as inline CSS variables; `styles.css` and page components **reference variables only** and
  never hard-code hex colours.
- Hard constraint for new UI: no colour literals in components; use antd tokens or existing
  classes such as `.stat-icon.tone-*` and `.user-avatar`. Theme switching only swaps colours
  and never changes layout, so neither size causes horizontal scrolling.

**2. Navigation groups by "what you want to do", not by endpoint**

Overview / Users & devices / Conversations & messages / Operations / Compliance /
Extensions. A new page first decides which group it belongs to instead of being appended to
the end of the menu.

**3. No internal jargon in the UI**

- No `§8.3`, `node_id`, `conv_id`, `PUT`, `422` — put explanations in `HelpTip` or `JsonPeek`;
- Table main columns always show the mapped copy (look it up in `lib/labels.ts`); raw
  English values only appear in the sub-row or "Technical details";
- Pages do not render big titles or intro paragraphs (the first row is content): put "what
  this page can do" into the filter row's `placeholder`, column-header `HelpTip` and the
  "Guide" button at the top right;
- Page-level action buttons go on the right of the filter row with
  `className="toolbar-right"`, never in the page header; when the row already has filter
  controls it lands rightmost via `margin-left: auto` + `order: 99`, and pages without
  filter controls first lay out an empty `.toolbar` row so button positions stay consistent;
- Every metric/number must answer "what counts as normal" in its hint;
- Raw JSON always goes into a `JsonPeek` block, never onto the page;
- Describe a risky action as "what will happen + whether it can be undone", not with
  implementation details.

**4. No page scrollbars; lists have a fixed height and scroll internally**

- The shell is fixed to one screen: `html/body/#root` and `.app-content` are all
  `overflow: hidden`, so a page-level scrollbar never appears;
- A list page root uses `className="page-fill"` and the main card `className="list-card"`:
  `.list-card` flexes to fill the remaining height, and `.ant-table` →
  `.ant-table-container` → `.ant-table-body` are all `flex:1 / min-height:0` channels, so
  **the table body fills the card's remaining height**;
- Table-body scrolling is triggered by `scroll={{ y: LIST_SCROLL_Y }}`
  (`components/listLayout.ts`) — it is required, otherwise antd does not split the header
  and body into two containers and scrolling moves to the page; the `y` value is overridden
  by CSS `max-height: none !important`, and the real height comes from the card. Do not try
  to fine-tune the height with `y`;
- Fixed page length `LIST_PAGE_SIZE = 12`, independent of viewport height (jumping heights
  make people lose their place); no horizontal `scroll={{ x }}`; column widths come from
  `table-layout: fixed` plus cell ellipsis;
- Row height 52px, header 42px (`.list-card` block in `styles.css`); long IDs ellipsize and
  never raise the row;
- Info pages (overview, config, keys, formats, plugins, offline queue) use
  `className="page-scroll"`: content may exceed one screen, it scrolls but the scrollbar is
  hidden (`scrollbar-width: none` + `::-webkit-scrollbar { width: 0 }`).

## Localisation

- English is the source language: user-visible strings are written inline as
  `t('English source')` from `useI18n()`; Chinese is an overlay keyed by the exact English
  string (`src/i18n/locales.zh.ts`), so a missing entry falls back to readable English
  instead of a raw key.
- Placeholders: `t('Signed in: {user}', { user })`.
- The language switch (English / Simplified Chinese) sits in the top bar immediately before
  the theme toggle, and in the login page's top-right corner. The choice is persisted in
  `localStorage['lattice.admin.locale']`, and `<html lang>` plus the dayjs locale follow it.
- Plain (non-hook) helpers such as `errText` and `fmtRelative` use the translator bound by
  `AuthProvider` (`bindTranslator` in `lib/labels.ts`).
- Chinese overlay part files live in `src/i18n/zh.parts/` (one JSON file per module) and are
  merged into `locales.zh.ts`.

## Page ↔ API mapping

| Page | Route | API (§8) |
| --- | --- | --- |
| Overview | `/` | **only** `stream` (SSE: `online` 1s / `node` 2s / `deps` 5s) — no polling, no initial GET |
| Users | `/users` | `users` (GET/POST), `quota`, `role`, `suspend`/`resume`, `purge` |
| Devices | `/devices` | `devices`, `DELETE devices/{id}` |
| Conversations | `/conversations` | `conversations`, `conversations/{id}` |
| Message search | `/messages` | `messages`, `messages/{id}/delivery` |
| Delivery failures | `/dlq` | `dlq`, `replay` |
| Offline queue | `/queue` | `queue`, `queue/purge` |
| Media recordings | `/recordings` | `media/recordings` (list/detail/download; admin/ops only; includes refresh time, loading skeleton, copy of the presigned URL / stream_id) |
| Audit log | `/audit` | `audit` |
| Plugin hub | `/hub` | `hub` (catalog/detail/publish + package upload/download/versions and plugin takedown/install records/stats) |
| Plugins | `/plugins` | `plugins` (GET/POST, incl. the WASM runtime status card), `plugins/{ns}/stats` |
| File formats | `/formats` | `formats` (GET/POST) |
| Dynamic config | `/config` | `config` (GET/PATCH) |
| Key management | `/keys` | `keys`, `keys/rotate` |

## Key implementation decisions

**1. Why decode the JWT ourselves**

The login response `user` object in §1.1 does **not** contain `role`; role only appears in
the access JWT (§0.2 "role source", a 900s snapshot). The console needs it for button-level
RBAC, so `auth/jwt.ts` decodes the payload — it only reads claims and does not verify the
signature (the server verifies it).

**2. Why refresh tokens are single-flight**

The §1.2 refresh is **rotating**: reusing the same refresh token returns `409 CONFLICT` and
revokes the whole chain. So 10 concurrent 401s must trigger only one refresh, otherwise the
user's own session is torn down. `api/http.ts` funnels concurrency through a module-level
`refreshing` promise.

**3. Why SSE does not use `EventSource`**

`/v1/admin/stream` uses `Authorization: Bearer`, and the native `EventSource` cannot send
custom request headers. `lib/useSse.ts` uses `fetch` + `ReadableStream` and parses the
`id:`/`event:`/`data:` frames by hand.

**3.1 Why the overview page has no timers (v0.13)**

Native `EventSource` reconnects on its own, so a hand-written implementation has to do it
too — `useSse` backs off 1s → 2s → ... → 30s and makes **zero requests** while connected.
The overview page's three blocks are each fed by an event: `online` (1s, online counts +
distribution), `node` (2s, node table), `deps` (5s, dependency health). That page therefore
has **no refresh button, no `setInterval` and no GET on load** — push is the only data
source.

On `429` (`details.reason=sse_limit`, 100-connection cap) the status shows "connection limit
exceeded" and it backs off to reconnect, **without falling back to polling**: a push-only
page has no polling fallback, and adding one would degrade "realtime" to "at most N seconds
old".

For the same reason the raw `metrics` text is not on the overview page: it is a whole
Prometheus text blob (thousands of lines), so pushing it is meaningless and wastes
bandwidth; use `GET /v1/admin/metrics` when needed.

**4. Why risky actions all go through `ReasonModal`**

§8 requires "a risky action must carry a `reason`, written to `audit_log.detail`"; without
it the server returns 422. One shared component avoids each call site writing its own and
missing a field.

**5. Idempotency key**

Every write request carries an `Idempotency-Key` by default (ULID, §0.3). A 401 replay
reuses the same key; if the server already executed it, the first result is returned and
side effects are not repeated.

**6. No payload display**

In zero-knowledge mode the server has no plaintext (§8.3). The messages page only shows
metadata and delivery details; `inspectable` mode's
`/v1/admin/messages/{id}/content` is a separate endpoint (admin + explicit reason + an audit
entry per call + P1 alert) and this console **does not integrate it**, avoiding misuse.

**7. Why hub publish is two steps and downloads go through a blob**

Publish: `POST /v1/hub/plugins` submits metadata only (including a `sha256` computed in the
browser with WebCrypto); after receiving `upload.path`, the raw bytes are `PUT` with an
`X-Content-SHA256` header. The version is invisible in the catalog until both steps succeed
(§12.3/§12.4). The console does not parse the zip; the manifest snapshot is generated from
form fields, and consistency with the package's `plugin.json` is enforced by the installing
client on download (② §4.9 trust model).

Download: `GET /v1/hub/.../download` requires `Authorization`, and `window.open` cannot
attach request headers; it also returns `302 → MinIO presigned URL`. Browser XHR follows
redirects automatically (the token is only used for the first hop; the presigned address
does not need it), so the console fetches final bytes with `responseType: 'blob'`,
re-verifies sha256 with WebCrypto and saves via `a[download]`. Cross-origin prerequisite:
the presigned address is not same-origin with the page, so object storage must allow the
console origin via CORS (dev MinIO echoes `Access-Control-Allow-Origin` for the request
origin and works in practice; standalone deployments must configure it explicitly).

## Contract differences (frontend aligned with the implementation, annotated on the pages)

| Item | Documentation | Current implementation | Frontend handling |
| --- | --- | --- | --- |
| `GET /v1/admin/audit` filters | `actor`/`action`/`target`/`from`/`to` | accepts only `actor`/`action`/`page`/`page_size` | exposes implemented parameters only and shows a note at the top so it never looks filtered when it is not |
| `GET /v1/admin/messages` | requires one of `id`/`conv`/`user` | same (`422 details.reason=selectivity`) | the frontend validates before sending |
| `GET /v1/admin/queue` | `?user=&scope=` | same | — |
| `GET /v1/admin/nodes` | `{items,total}` | same; since v0.13 each item also has `health`/`heartbeat_at` (previously only `healthy`, no heartbeat time) | — |
| `GET /v1/hub/plugins` catalog item | §12.1 does not list `install_enabled` | the implementation also returns `install_enabled` (enablement of the caller's install record, `null` when not installed) | used to mark "installed · disabled" |
| `POST /v1/hub/plugins` same version + same sha retry | returns `200` and "same draft" | if the version is already `published`, returns `200 { upload: null, idempotent: true }` | treats `upload=null` as "version already published" and skips the upload step |
| `my_install` on `GET /v1/hub/plugins/{id}` | "missing means no install record" | the key is always present, `null` when not installed | the frontend checks for `null` |

> Row 1 in the table above is a "documentation promises more than the implementation"
> gap; it was listed in this round's report and the docs have not been updated yet.

## Permissions (RBAC)

Buttons are hidden at the UI level, and the server still re-checks (unauthorised requests
return `403 FORBIDDEN`):

| Capability | viewer | ops | admin |
| --- | --- | --- | --- |
| Read (all lists/search/audit) | ✅ | ✅ | ✅ |
| Operate (ban/unban, revoke device, drain, replay, purge queue) | ❌ | ✅ | ✅ |
| Mutate (create account, change role, quota, purge, plugins, formats, config, key rotation) | ❌ | ❌ | ✅ |

> The table above only covers §8 admin surface. Exception: **media recordings** (§9.7
> `/v1/media/recordings*`) list/detail/download are gated server-side by
> `require_role(Ops)`; viewer/user always get `403`, and the console only shows the menu to
> admin/ops.
>
> The plugin hub (§12) is user-facing: catalog/publish/download/install records are open to
> **any signed-in account**; only the plugin owner or an admin can take down a plugin/version,
> and the page hides delete buttons based on `userId`/`role` from `useAuth`, while the server
> still re-checks.

## E2E / regression scripts (real browser CDP, read-only)

| Script | Covers | Expected |
| --- | --- | --- |
| `scripts/web-console-e2e.mjs` | login/overview/plugin hub/users/audit/messages/nodes/theme + CSV export | 25/25 |
| `.tooling/web-recordings-e2e.mjs` | media recordings menu/route/empty state/search/refresh/pagination/role gate | 34/34 |
| `scripts/web-roles-e2e.mjs` | admin/ops/user menu differences | 10/10 |
| `.tooling/web-account-e2e.mjs` | account menu (my profile/change password) + user row menu (edit profile/reset password) | 24/24 |
| `.tooling/web-ui-final-e2e.mjs` | 5 pages rendered + no horizontal scrolling (1440x900 / 1280x800) + avatar/role tag + WASM card + recordings refresh time/skeleton/empty state + light/dark theme tokens + console error | 70/70 |

How to run (prerequisites: web container on 8088, dev node on 8080, accounts from
`scripts/dev-reset-accounts.mjs`):

```cmd
node .tooling/web-ui-final-e2e.mjs
node scripts/web-console-e2e.mjs
node .tooling/web-recordings-e2e.mjs
node scripts/web-roles-e2e.mjs
node .tooling/web-account-e2e.mjs
```

> After changing `web/src`, rebuild with `npm run build` and sync `web/dist` to static
> hosting (for the dev container, `docker cp web/dist/. lattice-dev-web:/usr/share/nginx/html/`
> hot-deploys without restarting the container).

## Not done (explicit scope)

- Message content viewing (see "No payload display" above);
- Media recordings **in-browser playback/MP4 packaging**: the server currently stores raw
  `[4B len][body]` segment objects plus an index and does no transcoding, so `/recordings`
  only offers metadata + full-segment download; there is no player on the page;
- Result polling for `/v1/admin/keys/rotate` (currently only "accepted"; dual-key window
  information is on the keys page);
- Conversation member add/remove and topic subscription management are **messaging-surface**
  APIs (§3/§7), not admin APIs, so they are out of scope;
- Internationalisation: English source strings with a Chinese overlay (`src/i18n`), switched
  from the top bar or the login page.
