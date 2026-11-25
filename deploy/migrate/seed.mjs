#!/usr/bin/env node
// ---------------------------------------------------------------------------
// seed.mjs — one-shot dev -> production seed for the Lattice production stack.
//
// What it migrates (and nothing else):
//   * the three accounts admin (Eddie), ops (Lucas), user (Mia), password hashes
//     included, so the existing development credentials keep working;
//   * the published plugin catalog owned by those accounts;
//   * only the version each plugin currently points at as latest_version;
//   * each user's install records (data jsonb, data_rev, enabled, version).
//
// What it does NOT migrate: messages, conversations, devices, audit log, metrics,
// removed/test plugins, historical plugin versions.
//
// The plugin package and source objects referenced by the migrated versions are
// copied between MinIO instances through the S3 API with SigV4 signing, then the
// result is verified end-to-end (DB row fingerprints, catalog API, install API,
// 302 -> transfer-plane downloads, console reachability).
//
// Usage:
//   node deploy/migrate/seed.mjs
//
// Prerequisites:
//   * development stack up (deploy/compose/dev.yaml), containers lattice-dev-pg / -minio
//   * production stack up (deploy/migrate/init-prod.ps1), ready at 127.0.0.1:8180
// ---------------------------------------------------------------------------

import { execFileSync } from 'node:child_process'
import { createHash, createHmac } from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const ROOT = path.resolve(HERE, '..', '..')
const WORK = path.join(ROOT, '.dev', 'migrate')
const PROD_ENV = path.join(ROOT, 'deploy', 'config', 'prod.env')
const COMPOSE = 'deploy/compose/prod.yaml'

const DEV_PG = 'lattice-dev-pg'
const DEV_MINIO = 'lattice-dev-minio'
const PROD_PG = 'lattice-prod-pg'
const PROD_MINIO = 'lattice-prod-minio'
const PROD_NODE = 'lattice-prod-node'
const PROD_WEB = 'lattice-prod-web'

const NODE_URL = 'http://127.0.0.1:8180'
const TRANSFER_URL = 'http://127.0.0.1:8190'
const WEB_URL = 'http://127.0.0.1:8089'

const BUCKET = 'lattice-plugins'
const DB_USER = 'lattice_app'
const DB_NAME = 'lattice'
const MIGRATE_DIR = '/tmp/lattice-migrate'

const ACCOUNTS = [
  { username: 'admin', password: process.env.DEV_ADMIN_PASSWORD || 'lattice_dev_admin_pw', display: 'Eddie', role: 'admin' },
  { username: 'ops', password: process.env.DEV_OPS_PASSWORD || 'lattice_dev_ops_pw', display: 'Lucas', role: 'ops' },
  { username: 'user', password: process.env.DEV_USER_PASSWORD || 'lattice_dev_user_pw', display: 'Mia', role: 'user' },
]

const TARGET_USER_FILTER = "'admin', 'ops', 'user'"

// Fingerprints are computed with the identical filter on both databases: the
// production database must contain exactly the rows the development filter yields.
const FINGERPRINTS = {
  users: `select md5(string_agg(row_to_json(t)::text, '|' order by t.username)) from (
      select id, username, password_hash, display_name, status, role, capabilities, quota,
             created_at, updated_at, avatar
      from users where username in (${TARGET_USER_FILTER})
    ) t`,
  plugins: `select md5(string_agg(row_to_json(t)::text, '|' order by t.plugin_id)) from (
      select p.id, p.plugin_id, p.name, p.description, p.readme, p.icon, p.category, p.tags,
             p.owner_id, p.status, p.latest_version, p.downloads, p.created_at, p.updated_at
      from hub_plugins p join users u on u.id = p.owner_id
      where u.username in (${TARGET_USER_FILTER}) and p.status = 'published' and p.latest_version is not null
    ) t`,
  versions: `select md5(string_agg(row_to_json(t)::text, '|' order by t.plugin_id)) from (
      select v.id, v.plugin_row_id, v.version, v.asset_name, v.size, v.sha256, v.object_key,
             v.changelog, v.manifest, v.status, v.downloads, v.uploaded_by, v.published_at,
             v.created_at, v.source_asset_name, v.source_size, v.source_sha256, v.source_object_key,
             v.meta, v.review_note, v.reviewed_by, v.reviewed_at, v.submitted_at, p.plugin_id
      from hub_plugin_versions v
      join hub_plugins p on p.id = v.plugin_row_id
      join users u on u.id = p.owner_id
      where u.username in (${TARGET_USER_FILTER}) and p.status = 'published'
        and p.latest_version is not null and v.version = p.latest_version and v.status = 'published'
    ) t`,
  installs: `select md5(string_agg(row_to_json(t)::text, '|' order by t.user_id, t.plugin_id)) from (
      select i.user_id, i.plugin_id, i.version, i.enabled, i.data, i.data_rev,
             i.data_updated_at, i.updated_at
      from hub_plugin_installs i
      join users u on u.id = i.user_id
      join hub_plugins p on p.plugin_id = i.plugin_id
      where u.username in (${TARGET_USER_FILTER}) and p.status = 'published' and p.latest_version is not null
        and exists (select 1 from users o where o.id = p.owner_id and o.username in (${TARGET_USER_FILTER}))
    ) t`,
}

// ---------------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------------
function log(step, msg) {
  console.log(`[${step}] ${msg}`)
}

function fail(msg) {
  throw new Error(msg)
}

function docker(args, opts = {}) {
  return execFileSync('docker', args, { encoding: 'utf8', ...opts })
}

function dockerOut(args) {
  return docker(args).trim()
}

function psql(container, sql) {
  return dockerOut([
    'exec', container, 'psql', '-U', DB_USER, '-d', DB_NAME,
    '-v', 'ON_ERROR_STOP=1', '-t', '-A', '-F', '\t', '-c', sql,
  ])
}

function psqlFile(container, file) {
  docker([
    'exec', container, 'psql', '-U', DB_USER, '-d', DB_NAME,
    '-v', 'ON_ERROR_STOP=1', '-f', file,
  ], { stdio: 'inherit' })
}

function qrows(container, sql) {
  const out = psql(container, sql)
  return out.length === 0 ? [] : out.split('\n').map((line) => line.split('\t'))
}

function sha256(buf) {
  return createHash('sha256').update(buf).digest('hex')
}

function hmac(key, data) {
  return createHmac('sha256', key).update(data).digest()
}

function readEnvFile(file) {
  const env = {}
  for (const raw of fs.readFileSync(file, 'utf8').split(/\r?\n/)) {
    const line = raw.trim()
    if (!line || line.startsWith('#')) continue
    const eq = line.indexOf('=')
    if (eq <= 0) continue
    env[line.slice(0, eq).trim()] = line.slice(eq + 1).trim()
  }
  return env
}

async function waitHttp(url, timeoutMs = 180000, label = url) {
  const deadline = Date.now() + timeoutMs
  let last = ''
  while (Date.now() < deadline) {
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(3000) })
      if (res.ok) return res
      last = `HTTP ${res.status}`
    } catch (err) {
      last = String(err.message || err)
    }
    await new Promise((r) => setTimeout(r, 1000))
  }
  return fail(`timed out waiting for ${label}: ${last}`)
}

function requireRunning(name) {
  let running = ''
  try {
    running = dockerOut(['inspect', '-f', '{{.State.Running}}', name])
  } catch {
    fail(`container ${name} does not exist`)
  }
  if (running !== 'true') fail(`container ${name} is not running`)
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms))
}

// ---------------------------------------------------------------------------
// MinIO SigV4 (GET/HEAD/PUT; same signing model as the node's store/s3.rs)
// ---------------------------------------------------------------------------
function makeS3({ endpoint, accessKey, secretKey, region = 'us-east-1' }) {
  const base = new URL(endpoint)
  const prefix = base.pathname.replace(/\/+$/, '')

  return async function request(method, bucket, key, body = null, extraHeaders = {}) {
    const amzDate = new Date().toISOString().replace(/[-:]/g, '').replace(/\.\d{3}/, '')
    const date = amzDate.slice(0, 8)
    const payload = body ?? Buffer.alloc(0)
    const payloadHash = sha256(payload)
    const canonicalUri = `${prefix}/${bucket}/${key.split('/').map(encodeURIComponent).join('/')}`

    const headers = {
      host: base.host,
      'x-amz-content-sha256': payloadHash,
      'x-amz-date': amzDate,
      ...Object.fromEntries(Object.entries(extraHeaders).map(([k, v]) => [k.toLowerCase(), String(v)])),
    }
    const names = Object.keys(headers).sort()
    const canonicalHeaders = names.map((n) => `${n}:${headers[n].trim()}\n`).join('')
    const signedHeaders = names.join(';')
    const canonicalRequest = [method, canonicalUri, '', canonicalHeaders, signedHeaders, payloadHash].join('\n')
    const scope = `${date}/${region}/s3/aws4_request`
    const stringToSign = ['AWS4-HMAC-SHA256', amzDate, scope, sha256(Buffer.from(canonicalRequest))].join('\n')

    let signingKey = hmac(`AWS4${secretKey}`, date)
    signingKey = hmac(signingKey, region)
    signingKey = hmac(signingKey, 's3')
    signingKey = hmac(signingKey, 'aws4_request')
    const signature = createHmac('sha256', signingKey).update(stringToSign).digest('hex')

    const outHeaders = {
      ...headers,
      authorization: `AWS4-HMAC-SHA256 Credential=${accessKey}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`,
    }
    delete outHeaders.host

    return fetch(`${base.origin}${canonicalUri}`, {
      method,
      headers: outHeaders,
      body: method === 'PUT' ? payload : undefined,
      signal: AbortSignal.timeout(30000),
    })
  }
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
async function main() {
  if (!fs.existsSync(PROD_ENV)) fail(`missing ${PROD_ENV}; run deploy/migrate/init-prod.ps1 first`)
  const prodEnv = readEnvFile(PROD_ENV)
  for (const key of ['MINIO_ROOT_USER', 'MINIO_ROOT_PASSWORD', 'LATTICE__TRANSFER__SECRET']) {
    if (!prodEnv[key]) fail(`${PROD_ENV} is missing ${key}`)
  }

  log('0/9', 'preflight: containers, production readiness')
  for (const name of [DEV_PG, DEV_MINIO, PROD_PG, PROD_MINIO, PROD_NODE, PROD_WEB]) requireRunning(name)
  await waitHttp(`${NODE_URL}/v1/ready`, 180000, 'production node /v1/ready')
  await waitHttp(`${WEB_URL}/v1/health`, 60000, 'production console /v1/health')

  log('1/9', 'export filtered seed from the development database')
  docker(['exec', DEV_PG, 'mkdir', '-p', MIGRATE_DIR])
  docker(['exec', PROD_PG, 'mkdir', '-p', MIGRATE_DIR])
  docker(['cp', path.join(HERE, 'export.sql'), `${DEV_PG}:${MIGRATE_DIR}/export.sql`])
  docker(['cp', path.join(HERE, 'import.sql'), `${PROD_PG}:${MIGRATE_DIR}/import.sql`])
  psqlFile(DEV_PG, `${MIGRATE_DIR}/export.sql`)

  const devCounts = {
    users: Number(psql(DEV_PG, 'select count(*) from users where username in (' + TARGET_USER_FILTER + ')')),
    plugins: Number(psql(DEV_PG, `select count(*) from hub_plugins p join users u on u.id = p.owner_id
      where u.username in (${TARGET_USER_FILTER}) and p.status = 'published' and p.latest_version is not null`)),
    versions: Number(psql(DEV_PG, `select count(*) from hub_plugin_versions v join hub_plugins p on p.id = v.plugin_row_id
      join users u on u.id = p.owner_id where u.username in (${TARGET_USER_FILTER}) and p.status = 'published'
      and p.latest_version is not null and v.version = p.latest_version and v.status = 'published'`)),
    installs: Number(psql(DEV_PG, `select count(*) from hub_plugin_installs i join users u on u.id = i.user_id
      join hub_plugins p on p.plugin_id = i.plugin_id where u.username in (${TARGET_USER_FILTER})
      and p.status = 'published' and p.latest_version is not null
      and exists (select 1 from users o where o.id = p.owner_id and o.username in (${TARGET_USER_FILTER}))`)),
  }
  if (devCounts.users !== 3) fail(`expected 3 accounts in dev, found ${devCounts.users}`)

  const devFingerprints = {}
  for (const [name, sql] of Object.entries(FINGERPRINTS)) devFingerprints[name] = psql(DEV_PG, sql)

  // Snapshot the download counters so verification downloads can be undone.
  const devPluginDownloads = qrows(DEV_PG, `select p.plugin_id, p.downloads from hub_plugins p
    join users u on u.id = p.owner_id where u.username in (${TARGET_USER_FILTER})
    and p.status = 'published' and p.latest_version is not null`)
  const devVersionDownloads = qrows(DEV_PG, `select v.plugin_row_id, v.version, v.downloads
    from hub_plugin_versions v join hub_plugins p on p.id = v.plugin_row_id join users u on u.id = p.owner_id
    where u.username in (${TARGET_USER_FILTER}) and p.status = 'published' and p.latest_version is not null
    and v.version = p.latest_version and v.status = 'published'`)

  log('2/9', 'copy seed CSVs into the production database container')
  fs.rmSync(WORK, { recursive: true, force: true })
  fs.mkdirSync(WORK, { recursive: true })
  const csvFiles = ['users.csv', 'hub_plugins.csv', 'hub_plugin_versions.csv', 'hub_plugin_installs.csv']
  for (const file of csvFiles) {
    const local = path.join(WORK, file)
    docker(['cp', `${DEV_PG}:${MIGRATE_DIR}/${file}`, local])
    docker(['cp', local, `${PROD_PG}:${MIGRATE_DIR}/${file}`])
  }

  log('3/9', 'import into the production database (transactional)')
  psqlFile(PROD_PG, `${MIGRATE_DIR}/import.sql`)

  log('4/9', 'verify row fingerprints and counts')
  const prodCounts = {
    users: Number(psql(PROD_PG, 'select count(*) from users')),
    plugins: Number(psql(PROD_PG, 'select count(*) from hub_plugins')),
    versions: Number(psql(PROD_PG, 'select count(*) from hub_plugin_versions')),
    installs: Number(psql(PROD_PG, 'select count(*) from hub_plugin_installs')),
  }
  for (const key of Object.keys(devCounts)) {
    if (prodCounts[key] !== devCounts[key]) {
      fail(`count mismatch for ${key}: dev ${devCounts[key]} vs prod ${prodCounts[key]}`)
    }
  }
  for (const [name, sql] of Object.entries(FINGERPRINTS)) {
    const prod = psql(PROD_PG, sql)
    if (prod !== devFingerprints[name]) fail(`fingerprint mismatch for ${name}: dev ${devFingerprints[name]} vs prod ${prod}`)
    log('4/9', `  ${name}: ${prodCounts[name]} rows, fingerprint ${devFingerprints[name]}`)
  }

  log('5/9', 'copy plugin package/source objects to production MinIO')
  const devS3 = makeS3({ endpoint: 'http://127.0.0.1:9000', accessKey: 'lattice_dev', secretKey: 'lattice_dev_secret' })
  const prodS3 = makeS3({ endpoint: 'http://127.0.0.1:9002', accessKey: prodEnv.MINIO_ROOT_USER, secretKey: prodEnv.MINIO_ROOT_PASSWORD })
  const versionObjects = qrows(PROD_PG, `select p.plugin_id, v.version, v.object_key, v.size::text, v.sha256,
      coalesce(v.source_object_key, ''), coalesce(v.source_size::text, ''), coalesce(v.source_sha256, '')
    from hub_plugin_versions v join hub_plugins p on p.id = v.plugin_row_id order by p.plugin_id`)

  let copied = 0
  let copiedBytes = 0
  for (const [pluginId, version, objectKey, size, sha, sourceKey, sourceSize, sourceSha] of versionObjects) {
    const targets = [{ key: objectKey, size: Number(size), sha }]
    if (sourceKey) targets.push({ key: sourceKey, size: Number(sourceSize), sha: sourceSha })
    for (const target of targets) {
      const head = await devS3('HEAD', BUCKET, target.key)
      if (!head.ok) fail(`dev object missing: ${target.key} -> HTTP ${head.status}`)
      const contentType = head.headers.get('content-type') || 'application/zip'

      const got = await devS3('GET', BUCKET, target.key)
      if (!got.ok) fail(`dev object read failed: ${target.key} -> HTTP ${got.status}`)
      const bytes = Buffer.from(await got.arrayBuffer())
      if (bytes.length !== target.size) fail(`dev object size mismatch for ${target.key}: ${bytes.length} != ${target.size}`)
      if (sha256(bytes) !== target.sha) fail(`dev object sha mismatch for ${target.key}`)

      const put = await prodS3('PUT', BUCKET, target.key, bytes, { 'content-type': contentType })
      if (![200, 201, 204].includes(put.status)) {
        fail(`prod object write failed: ${target.key} -> HTTP ${put.status}: ${(await put.text()).slice(0, 200)}`)
      }
      const back = await prodS3('GET', BUCKET, target.key)
      if (!back.ok) fail(`prod object read-back failed: ${target.key} -> HTTP ${back.status}`)
      const backBytes = Buffer.from(await back.arrayBuffer())
      if (backBytes.length !== target.size || sha256(backBytes) !== target.sha) {
        fail(`prod object verification failed: ${target.key}`)
      }
      copied += 1
      copiedBytes += backBytes.length
    }
    log('5/9', `  ${pluginId}@${version}: ${targets.length} object(s) verified`)
  }

  log('6/9', 'restart the production node so no pre-seed state is cached')
  docker(['restart', PROD_NODE], { stdio: 'inherit' })
  await waitHttp(`${NODE_URL}/v1/ready`, 180000, 'production node after restart')

  log('7/9', 'verify through the public API (login, catalog, installs, downloads)')
  const tokens = {}
  for (const account of ACCOUNTS) {
    const res = await fetch(`${NODE_URL}/v1/auth/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ username: account.username, password: account.password, device_name: 'migration-verify' }),
      signal: AbortSignal.timeout(15000),
    })
    const json = await res.json().catch(() => null)
    if (res.status !== 200 || !json?.access_jwt) {
      fail(`login failed for ${account.username}: HTTP ${res.status} ${JSON.stringify(json).slice(0, 200)}`)
    }
    if (json.user?.display_name !== account.display) {
      fail(`login for ${account.username} returned display_name ${json.user?.display_name}, expected ${account.display}`)
    }
    tokens[account.username] = json.access_jwt
    log('7/9', `  ${account.username}: login ok (${json.user.display_name})`)
  }

  async function api(username, pathname) {
    const res = await fetch(NODE_URL + pathname, {
      headers: { authorization: `Bearer ${tokens[username]}` },
      signal: AbortSignal.timeout(15000),
    })
    const json = await res.json().catch(() => null)
    if (!res.ok) fail(`GET ${pathname} as ${username} -> HTTP ${res.status} ${JSON.stringify(json).slice(0, 200)}`)
    return json
  }

  const expectedPlugins = qrows(DEV_PG, `select p.plugin_id, p.latest_version, lv.size
    from hub_plugins p
    join users u on u.id = p.owner_id
    join hub_plugin_versions lv on lv.plugin_row_id = p.id and lv.version = p.latest_version
    where u.username in (${TARGET_USER_FILTER}) and p.status = 'published' and p.latest_version is not null
    order by p.plugin_id`)

  const catalog = await api('admin', '/v1/hub/plugins?page_size=100')
  const catalogById = new Map((catalog.items || []).map((item) => [item.plugin_id, item]))
  if (catalogById.size !== expectedPlugins.length) {
    fail(`catalog has ${catalogById.size} plugins, expected ${expectedPlugins.length}: ${JSON.stringify([...catalogById.keys()])}`)
  }
  for (const [pluginId, latestVersion, size] of expectedPlugins) {
    const item = catalogById.get(pluginId)
    if (!item) fail(`catalog is missing ${pluginId}`)
    if (item.latest_version !== latestVersion) fail(`catalog ${pluginId} latest_version ${item.latest_version} != ${latestVersion}`)
    if (Number(item.size) !== Number(size)) fail(`catalog ${pluginId} size ${item.size} != ${size}`)
    if (item.versions_count !== 1) fail(`catalog ${pluginId} exposes ${item.versions_count} versions, expected only the latest`)
  }
  log('7/9', `  catalog: ${catalogById.size} published plugins, only latest versions`)

  const expectedInstalls = qrows(DEV_PG, `select u.username, i.plugin_id, i.version, i.enabled, i.data_rev
    from hub_plugin_installs i join users u on u.id = i.user_id join hub_plugins p on p.plugin_id = i.plugin_id
    where u.username in (${TARGET_USER_FILTER}) and p.status = 'published' and p.latest_version is not null
    order by u.username, i.plugin_id`)
  const installsByUser = { admin: [], ops: [], user: [] }
  for (const row of expectedInstalls) installsByUser[row[0]].push(row)
  for (const username of ['admin', 'ops', 'user']) {
    const payload = await api(username, '/v1/hub/installs?include_data=1')
    const items = payload.items || []
    const expected = installsByUser[username]
    if (items.length !== expected.length) fail(`${username} installs: ${items.length} != ${expected.length}`)
    const byPlugin = new Map(items.map((item) => [item.plugin_id, item]))
    for (const [, pluginId, version, enabled, dataRev] of expected) {
      const item = byPlugin.get(pluginId)
      if (!item) fail(`${username} is missing install record for ${pluginId}`)
      if (item.version !== version) fail(`${username}/${pluginId} version ${item.version} != ${version}`)
      if (Boolean(item.enabled) !== (enabled === 't')) fail(`${username}/${pluginId} enabled mismatch`)
      if (Number(item.data_rev) !== Number(dataRev)) fail(`${username}/${pluginId} data_rev ${item.data_rev} != ${dataRev}`)
      if (item.data === null || item.data === undefined) fail(`${username}/${pluginId} data payload missing`)
    }
    log('7/9', `  installs for ${username}: ${items.length} record(s) with data intact`)
  }

  const mine = { admin: (await api('admin', '/v1/hub/mine')).items || [], user: (await api('user', '/v1/hub/mine')).items || [] }
  if (mine.admin.length !== 3) fail(`admin owns ${mine.admin.length} plugins, expected 3`)
  if (mine.user.length !== 1 || mine.user[0].plugin_id !== 'global-time-zones') fail('Mia plugin ownership did not migrate')

  for (const [pluginId, version, objectKey, size, sha, , sourceSize, sourceSha] of versionObjects) {
    for (const kind of ['download', 'source']) {
      if (kind === 'source' && !sourceSize) continue
      const pathname = `/v1/hub/plugins/${pluginId}/versions/${version}/${kind}`
      const res = await fetch(NODE_URL + pathname, {
        headers: { authorization: `Bearer ${tokens.admin}` },
        redirect: 'manual',
        signal: AbortSignal.timeout(15000),
      })
      if (res.status !== 302) fail(`${kind} for ${pluginId}@${version} returned HTTP ${res.status}, expected 302`)
      const location = res.headers.get('location')
      const expectedSha = kind === 'download' ? sha : sourceSha
      if (res.headers.get('x-content-sha256') !== expectedSha) fail(`${kind} ${pluginId}@${version} sha header mismatch`)
      const tokenPath = new URL(location, NODE_URL).pathname + new URL(location, NODE_URL).search
      const body = await fetch(TRANSFER_URL + tokenPath, { signal: AbortSignal.timeout(30000) })
      if (!body.ok) fail(`transfer plane for ${kind} ${pluginId}@${version} -> HTTP ${body.status}`)
      const bytes = Buffer.from(await body.arrayBuffer())
      if (sha256(bytes) !== expectedSha) fail(`transfer hash mismatch for ${kind} ${pluginId}@${version}`)
      log('7/9', `  ${kind}: ${pluginId}@${version} -> ${bytes.length} bytes, sha256 ok`)
    }
  }

  const badToken = await fetch(`${TRANSFER_URL}/t/not-a-token`, { signal: AbortSignal.timeout(5000) })
  if (badToken.status !== 404) fail(`invalid transfer token returned HTTP ${badToken.status}, expected 404`)

  const page = await fetch(WEB_URL + '/', { signal: AbortSignal.timeout(10000) })
  const html = await page.text()
  if (!page.ok || !html.includes('id="root"')) fail(`console at ${WEB_URL} is not serving the SPA (HTTP ${page.status})`)
  log('7/9', `  console: ${WEB_URL} serving SPA`)

  log('8/9', 'restore download counters and clean verification artifacts')
  await sleep(1500)
  for (const [pluginId, downloads] of devPluginDownloads) {
    psql(PROD_PG, `update hub_plugins set downloads = ${Number(downloads)} where plugin_id = '${pluginId}'`)
  }
  for (const [pluginRowId, version, downloads] of devVersionDownloads) {
    psql(PROD_PG, `update hub_plugin_versions set downloads = ${Number(downloads)}
      where plugin_row_id = '${pluginRowId}' and version = '${version}'`)
  }
  await sleep(1000)
  for (const [name, sql] of Object.entries(FINGERPRINTS)) {
    const prod = psql(PROD_PG, sql)
    if (prod !== devFingerprints[name]) fail(`fingerprint drift after verification for ${name}`)
  }
  log('8/9', '  download counters restored')

  log('9/9', 'remove the one-shot bootstrap password and reload the node')
  const envText = fs.readFileSync(PROD_ENV, 'utf8')
  fs.writeFileSync(PROD_ENV, envText.replace(/^LATTICE__ADMIN__BOOTSTRAP_PASSWORD=.*$/m, 'LATTICE__ADMIN__BOOTSTRAP_PASSWORD='))
  // --no-deps: only recreate the node, never the database/object store it depends on.
  docker(['compose', '-f', COMPOSE, 'up', '-d', '--no-deps', '--force-recreate', 'node'], { cwd: ROOT, stdio: 'inherit' })
  await waitHttp(`${NODE_URL}/v1/ready`, 180000, 'production node after bootstrap removal')
  // nginx caches the node upstream address at start, so reload it after a node recreate.
  docker(['compose', '-f', COMPOSE, 'up', '-d', '--no-deps', '--force-recreate', 'web'], { cwd: ROOT, stdio: 'inherit' })
  await waitHttp(`${WEB_URL}/v1/health`, 120000, 'production console after reload')

  // Cleanup runs last: with the NATS bus enabled the audit writer is asynchronous, so
  // deleting earlier can race a late consumer write.
  psql(PROD_PG, 'delete from devices; truncate audit_log;')
  await sleep(1500)
  const residual =
    Number(psql(PROD_PG, 'select count(*) from devices')) +
    Number(psql(PROD_PG, 'select count(*) from audit_log'))
  if (residual !== 0) fail(`verification artifacts reappeared (${residual} rows); the audit consumer is replaying`)

  // The staging CSVs contain password hashes and user plugin data; drop them from the
  // host and from both database containers once the seed has been verified.
  fs.rmSync(WORK, { recursive: true, force: true })
  docker(['exec', DEV_PG, 'rm', '-rf', MIGRATE_DIR])
  docker(['exec', PROD_PG, 'rm', '-rf', MIGRATE_DIR])
  log('9/9', '  staging CSVs removed (host + both database containers)')

  const finalCounts = {
    users: Number(psql(PROD_PG, 'select count(*) from users')),
    hub_plugins: Number(psql(PROD_PG, 'select count(*) from hub_plugins')),
    hub_plugin_versions: Number(psql(PROD_PG, 'select count(*) from hub_plugin_versions')),
    hub_plugin_installs: Number(psql(PROD_PG, 'select count(*) from hub_plugin_installs')),
    devices: Number(psql(PROD_PG, 'select count(*) from devices')),
    messages: Number(psql(PROD_PG, 'select count(*) from messages')),
    conversations: Number(psql(PROD_PG, 'select count(*) from conversations')),
  }
  if (finalCounts.users !== 3) fail(`final user count is ${finalCounts.users}, expected 3`)
  if (finalCounts.devices !== 0 || finalCounts.messages !== 0 || finalCounts.conversations !== 0) {
    fail(`production holds out-of-scope rows: ${JSON.stringify(finalCounts)}`)
  }

  console.log('')
  console.log('Migration complete.')
  console.table(finalCounts)
  console.log(`objects copied : ${copied} (${copiedBytes} bytes)`)
  console.log(`console        : ${WEB_URL}`)
  console.log(`accounts       : admin/Eddie, ops/Lucas, user/Mia (development passwords preserved)`)
}

main().catch((err) => {
  console.error('')
  console.error('SEED FAILED:', err.message)
  process.exitCode = 1
})
