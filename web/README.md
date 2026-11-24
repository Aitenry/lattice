# Lattice administration console

The web console for Lattice operators and administrators. It covers the admin plane of the platform API: users and devices, conversations and messages, delivery failures and the offline queue, media recordings, the audit log, the plugin catalog and review queue, server plugins, file formats, dynamic configuration, and key management.

Stack: Vite 5, React 18, TypeScript 5, Ant Design 5, Axios 1.7.

## Quick start

```bash
cd web
npm ci
npm run dev
```

The dev server listens on http://127.0.0.1:5173 and proxies `/v1` to `http://127.0.0.1:8080`. To use a different node:

```bash
VITE_API_TARGET=http://10.0.0.5:8080 npm run dev
```

Production build and verification:

```bash
npm run build     # TypeScript check + Vite build into web/dist
npm run verify    # same checks through scripts/verify.mjs
```

`web/dist` is static output. Serve it behind a same-origin proxy that forwards `/v1` to the node, including the WebSocket upgrade on `/v1/ws`.

## Accounts

The console has no self-registration flow. The first administrator is created by the node during startup from the configured bootstrap credentials:

```toml
[admin]
bootstrap_username = "admin"
bootstrap_password = "change-me"
```

The local development default is defined in `deploy/config/dev.toml` and is intended for local use only. After signing in, create further accounts under **Users → New account**; the server enforces role and permission checks independently of the UI.

## Directory layout

```
web/
├── vite.config.ts             Dev server and /v1 proxy
├── src/
│   ├── theme.ts               Design tokens: antd light/dark themes and CSS variables
│   ├── styles.css             Layout skeleton; colours come from CSS variables only
│   ├── api/
│   │   ├── http.ts            Axios client: JWT, single-flight refresh, error normalisation, idempotency key
│   │   ├── endpoints.ts       Typed calls for every admin endpoint
│   │   └── types.ts           API contract types
│   ├── auth/
│   │   ├── AuthProvider.tsx   Session, device fingerprint, decoded role
│   │   ├── jwt.ts             Reads claims from the access token
│   │   └── rbac.ts            Capability matrix, role labels, role colours
│   ├── components/            Shared drawers, dialogs, tags, avatars, JSON viewer, help tips
│   ├── i18n/                  English source strings and the Simplified Chinese overlay
│   ├── layout/AppLayout.tsx   Navigation, top bar, language and theme switches, account menu
│   ├── lib/                   SSE client, formatting, labels, CSV export, ULID helper
│   └── pages/                 Login and 18 console pages
└── README.md
```

## Pages

| Page | Route | Access | Purpose |
| --- | --- | --- | --- |
| Dashboard | `/` | admin, ops | Live online counts, node health, dependency health; pushed over one SSE stream, with REST polling only as a fallback |
| Users | `/users` | admin, ops | Search accounts; create accounts; edit profile; reset password; change role; set quota; suspend, resume, or purge |
| Devices | `/devices` | admin, ops, user | Registered devices and fingerprints; revoke a device |
| Server nodes | `/nodes` | admin, ops | Node table with health, heartbeat, and drain controls |
| Media recordings | `/recordings` | admin, ops | Recording index, metadata, manifest, and segment download |
| Conversations | `/conversations` | admin, ops, user | Conversation list and members; message counts |
| Broadcast topics | `/topics` | admin, ops, user | Topic subscriptions and retained history |
| Message search | `/messages` | admin, ops, user | Message metadata and per-device delivery state; no payload content |
| Delivery failures | `/dlq` | admin, ops | Dead-letter entries and replay |
| Offline queue | `/queue` | admin, ops | Pending depth per user or device; purge with a cutoff |
| Audit log | `/audit` | admin, ops | Administrative and security events |
| Plugin hub | `/hub` | admin, ops, user | Browse, publish, download, install, and manage desktop plugins |
| My plugin data | `/hub-data` | admin, ops, user | Read-only view of the signed-in account's synced install records and JSON data snapshots |
| Plugin review | `/hub-review` | admin | Approve or reject submitted plugin versions |
| Server plugins | `/plugins` | admin | Format-plugin registry and WASM runtime status |
| File formats | `/formats` | admin, ops | Registered format handlers and their capabilities |
| Dynamic config | `/config` | admin | Runtime limits, feature switches, and rollout percentages |
| Key management | `/keys` | admin | Current signing key, overlap window, rotation |
| Login | `/login` | public | Credential and device-fingerprint sign-in |

The navigation groups pages by task, not by endpoint: the dashboard is pinned above six collapsible groups, and opening one group closes the previous one. The groups are **Messaging**, **Users & devices**, **Operations**, **Plugins & extensions**, **Platform settings**, and **Compliance**.

## Visual and copy conventions

These rules keep the console consistent and readable. They are reviewed as part of UI changes.

**Colours come from one source.** Primary, sidebar, background, card, border, and status colours live in `theme.ts`. Pages use antd tokens or the CSS variables injected by `ThemeProvider`; components never hard-code hex values. Status colours are semantic: green healthy, red failed, orange warning, blue processing.

**One navigation grid.** Every sidebar row is the same 36px line with a 16px icon and a 14px label: level 1 (the pinned dashboard and each group header) sits on the rail gutter (icon at 20px, label at 46px), and level 2 (a group's children) steps in exactly one column (icon at 34px, label at 60px), so depth never adds more than a single 14px step. Row height, icon size, type size and both indents are `--nav-*` variables on `.sider-menu` in `styles.css`; change them there, not per rule. Second-level labels stay four Chinese characters (`插件中心`, `插件数据`, `服务节点`, …) so the column reads as one block.

**Light and dark themes.** The top-bar toggle switches the antd algorithm and the CSS variable set. The choice is stored in `localStorage['lattice.admin.theme']`; light is the default so the visual baseline is stable. Theme switching changes colour only, never layout.

**No internal jargon in the UI.** Identifiers such as `node_id` or `conv_id`, protocol names, and raw HTTP status codes belong in a help tip or the collapsed technical-details block, not in table columns or page copy. Table columns show the mapped label from `lib/labels.ts`; raw values appear only in sub-rows or the technical-details panel.

**One page frame.** Every console page uses the same full-height card with a toolbar:

```tsx
<div className="page-fill">
  <Card className="list-card">
    <div className="toolbar">filters and counts <div className="toolbar-right">page actions</div></div>
    <div className="card-scroll">content</div>
  </Card>
</div>
```

- No page-level scrollbar; `html`, `body`, `#root`, and `.app-content` are fixed-height and the card fills the remaining space.
- Tables use `size="small"`, `scroll={{ y: LIST_SCROLL_Y }}`, `LIST_PAGE_SIZE`, and `showSizeChanger: false`. Columns ellipsize; tables do not scroll horizontally.
- Metrics use a `.metric-strip` inside the card, not a row of separate stat cards.
- Cursor-paged lists keep previous/next controls in the card footer.
- Toolbar order: filters, muted count, then right-aligned actions. Refresh is secondary; the primary action is last.
- Raw JSON always goes into the collapsible technical-details block, never onto the page.

**Localisation.** English is the source language: strings are written inline through `t('English source')`. Simplified Chinese is an overlay keyed by the exact English string, so a missing entry falls back to readable English. Placeholders use `t('Signed in: {user}', { user })`. The language choice is stored in `localStorage['lattice.admin.locale']`, and `<html lang>` plus the dayjs locale follow it. Plain helpers use the translator bound by `AuthProvider`.

## Implementation notes

**Role decoding.** The login response does not include the role; it is a claim inside the access token. `auth/jwt.ts` decodes the payload to drive button-level visibility. The signature is verified by the server, never by the browser.

**Single-flight token refresh.** Refresh tokens rotate: reusing an old refresh token revokes the chain. Concurrent `401` responses therefore share one refresh promise in `api/http.ts`, so a page with several parallel requests cannot tear down its own session.

**Server-sent events.** The admin stream requires an `Authorization` header, which the native `EventSource` cannot send. `lib/useSse.ts` uses `fetch` and parses `id:`, `event:`, and `data:` frames. It reconnects with backoff from 1s to 30s and makes no requests while connected. The dashboard consumes three event types: online counts, node snapshots, and dependency health. If the connection limit is reached, the page falls back to a five-second REST snapshot and keeps reconnecting; push resumes automatically.

**Risky actions.** Destructive or sensitive operations require a reason through the shared `ReasonModal`. The server records the reason in the audit detail and rejects requests without it.

**Idempotency.** Every write sends an `Idempotency-Key` (a ULID). A retry after a `401` reuses the same key, so the server returns the first result instead of repeating side effects.

**No payload display.** In zero-knowledge mode the server has no plaintext. The message search page shows metadata and delivery state only. The inspectable-mode content endpoint is intentionally not integrated into this console, to avoid casual content access.

**Plugin publication and download.** Publishing is two steps: submit metadata, then upload the package bytes to the returned path with a client-computed SHA-256. A version is not visible until both steps succeed. Downloads require an `Authorization` header and end in a presigned object-storage redirect; the console fetches the final bytes as a blob, verifies SHA-256 in the browser, and saves the file. Object storage must allow the console origin through CORS for this flow to work across origins.

## Permissions

The UI hides actions a role cannot perform. The server re-checks every request and returns `403 FORBIDDEN` when the role is insufficient.

| Capability | user | ops | admin |
| --- | --- | --- | --- |
| Read own account, devices, conversations, messages, topics, and hub data | yes | yes | yes |
| Read other accounts' data (users, devices, conversations, messages, audit, queue, recordings) | no | yes | yes |
| Operate (suspend, revoke any device, drain, replay, purge queue) | no (own device revoke only) | yes | yes |
| Mutate (create account, change role, quota, purge, plugins, formats, config, key rotation) | no | no | yes |
| Approve or reject plugin submissions | no | no | yes |

The `user` role is server-scoped to its own rows: the user list returns its own record, devices return its own devices, and conversations, messages, and topics are filtered to its memberships. Audit, queue, dead-letter, recordings, online metrics, and node data return `403`. The console hides those menus for `user` and redirects a typed forbidden URL to the plugin hub.

Media recordings remain ops/admin-only: the recording index has no participant attribution, so the server cannot safely derive a per-user list. Exposing the global list to `user` would reveal other accounts' sessions.

## Verification

`npm run verify` performs the TypeScript check and the production build. For UI changes, also verify the following manually against a running dev stack:

1. Sign in as each role and confirm the visible menu matches the permissions table.
2. Open the dashboard and confirm online, node, and dependency blocks update over SSE without a page reload.
3. Load every list page at 1440×900 and 1280×800 and confirm no horizontal scrolling and no clipped columns.
4. Toggle light and dark themes and confirm every surface and status colour remains readable.
5. Perform one destructive action with a reason, confirm it succeeds, then repeat without a reason and confirm the server rejects it.
6. Publish a plugin version, confirm it stays invisible in the catalog until an administrator approves it, then download it and confirm the SHA-256 check passes.

## Current scope

- Message content is not shown; only metadata and delivery state are available in zero-knowledge mode.
- Media recordings support metadata, manifest, and full-segment download. There is no in-browser playback or MP4/OGG packaging because the server stores raw segments without transcoding.
- Key rotation shows the accepted state and the dual-key window; it does not poll for completion.
- Conversation member management and topic subscription management are messaging-surface operations, not admin operations, and are outside this console.
- English and Simplified Chinese are the supported interface languages.
