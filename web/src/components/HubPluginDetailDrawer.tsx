import { useEffect, useRef, useState } from 'react'
import { Alert, Button, Card, Drawer, Popconfirm, Space, Spin, Table, Tag, Tooltip, Typography } from 'antd'
import { CodeOutlined, DeleteOutlined, DownOutlined, DownloadOutlined, UpOutlined } from '@ant-design/icons'
import type { HubPluginDetail, HubVersionRow, HubVersionStatus } from '@/api/types'
import { HelpTip } from '@/components/HelpTip'
import { JsonPeek } from '@/components/JsonPeek'
import { PluginIcon } from '@/components/PluginIcon'
import { useI18n, type Translate } from '@/i18n'
import { fmtBytes, fmtRelative, fmtTime } from '@/lib/format'
import { HUB_CATEGORY, hubOwnerLabel, pick } from '@/lib/labels'

/**
 * Plugin detail drawer (`/hub` catalogue).
 *
 * Layout rules this component follows:
 * - one identity block (icon, name, version, category, ID, summary) instead of repeating the
 *   name in the drawer title and again in the body;
 * - publisher / downloads / dates collapse into one four-cell strip, so the drawer does not
 *   spend half a screen on four labels;
 * - the version table is the only place with row actions, and it is sized to fit the drawer:
 *   no horizontal overflow, no clipped buttons, no second "source" column that duplicated
 *   the download affordance;
 * - the readme is clamped with an explicit expand toggle, so a 16 KiB README can never push
 *   the version list (the actual task) out of reach;
 * - the drawer body keeps a slim, visible scrollbar: long content is discoverable.
 */

/** Collapsed readme height (five 13px/1.75 lines); anything taller gets an expand toggle */
const README_CLAMP_PX = 114

/**
 * Review state of one version (its own column).
 *
 * Every state is shown: the column exists to expose the review flow, so a published version
 * gets a green tag instead of an empty cell.
 */
function versionStatusTag(status: HubVersionStatus | undefined, t: Translate) {
  switch (status) {
    case 'review':
      return (
        <Tag color="orange" style={{ marginInlineEnd: 0 }}>
          {t('In review')}
        </Tag>
      )
    case 'rejected':
      return (
        <Tag color="red" style={{ marginInlineEnd: 0 }}>
          {t('Review rejected')}
        </Tag>
      )
    case 'pending':
      return (
        <Tag style={{ marginInlineEnd: 0 }}>
          {t('Not submitted')}
        </Tag>
      )
    case 'published':
    default:
      return (
        <Tag color="green" style={{ marginInlineEnd: 0 }}>
          {t('Released')}
        </Tag>
      )
  }
}

export interface HubPluginDetailDrawerProps {
  open: boolean
  loading: boolean
  detail: HubPluginDetail | null
  /** Publisher or admin: may remove the plugin and single versions */
  canManage: boolean
  /** Version whose package is being downloaded (button spinner) */
  downloading: string | null
  /** Version whose source archive is being downloaded (button spinner) */
  downloadingSource: string | null
  onClose: () => void
  onDownload: (row: HubVersionRow) => void
  onDownloadSource: (row: HubVersionRow) => void
  onDeleteVersion: (version: string) => void
  onDeletePlugin: () => void
}

type DetailBodyProps = Omit<HubPluginDetailDrawerProps, 'open' | 'loading'> & { detail: HubPluginDetail }

export function HubPluginDetailDrawer(props: HubPluginDetailDrawerProps) {
  const { t } = useI18n()
  const { detail } = props

  return (
    <Drawer
      open={props.open}
      onClose={props.onClose}
      width={800}
      destroyOnClose
      rootClassName="hub-detail-drawer"
      title={t('Plugin details')}
      styles={{ body: { padding: '18px 20px 24px' } }}
      extra={
        props.canManage && detail ? (
          <Popconfirm
            title={t('Remove this plugin?')}
            description={t('Once removed it disappears from the catalogue and other users cannot download it. Install records are kept and come back if the same plugin is published again. Packages are kept for 30 days before automatic cleanup.')}
            okText={t('Remove')}
            okButtonProps={{ danger: true }}
            cancelText={t('Cancel')}
            onConfirm={props.onDeletePlugin}
          >
            <Button danger size="small" icon={<DeleteOutlined />}>
              {t('Remove plugin')}
            </Button>
          </Popconfirm>
        ) : null
      }
    >
      {props.loading ? (
        <div className="hub-detail-loading">
          <Spin />
        </div>
      ) : detail ? (
        <HubPluginDetailBody key={detail.plugin_id} {...props} detail={detail} />
      ) : null}
    </Drawer>
  )
}

function HubPluginDetailBody(props: DetailBodyProps) {
  const { t } = useI18n()
  const { detail, canManage, downloading, downloadingSource } = props
  const [readmeExpanded, setReadmeExpanded] = useState(false)
  const [readmeOverflows, setReadmeOverflows] = useState(false)
  const readmeTextRef = useRef<HTMLDivElement>(null)

  // Measure the unclamped text: only content that really does not fit gets the toggle.
  // The drawer mounts hidden while it slides in (height reads 0 there), so a ResizeObserver
  // re-measures as soon as the layout is real — and again after a resize.
  useEffect(() => {
    const el = readmeTextRef.current
    if (!el) return
    const measure = () => setReadmeOverflows(el.offsetHeight > README_CLAMP_PX + 4)
    measure()
    const observer = new ResizeObserver(measure)
    observer.observe(el)
    return () => observer.disconnect()
  }, [detail.readme])

  const latestRow = detail.versions.find((v) => v.version === detail.latest_version) ?? null
  const rejectedNotes = detail.versions.filter((v) => v.status === 'rejected' && v.review_note)
  const readme = detail.readme?.trim() ? detail.readme : null
  const install = detail.my_install

  return (
    <div className="hub-detail">
      {/* ---------- Identity ---------- */}
      <div className="hub-hero">
        <PluginIcon icon={detail.icon} name={detail.name} size={54} />
        <div className="hub-hero-main">
          <div className="hub-hero-title">
            <span className="hub-hero-name">{detail.name}</span>
            <Tag color="blue" style={{ marginInlineEnd: 0 }}>
              {detail.latest_version ?? t('No downloadable version')}
            </Tag>
            <Tag style={{ marginInlineEnd: 0 }}>{t(pick(HUB_CATEGORY, detail.category, detail.category))}</Tag>
          </div>
          <div className="hub-hero-id">{detail.plugin_id}</div>
          <Typography.Paragraph
            type="secondary"
            style={{ margin: 0, fontSize: 13, lineHeight: 1.6 }}
            ellipsis={{ rows: 2, tooltip: detail.description || undefined }}
          >
            {detail.description || t('No description from the publisher')}
          </Typography.Paragraph>
          {detail.tags.length > 0 && (
            <div className="hub-hero-tags">
              {detail.tags.map((tag) => (
                <Tag key={tag} style={{ marginInlineEnd: 0 }}>
                  {tag}
                </Tag>
              ))}
            </div>
          )}
        </div>
        {latestRow && (
          <Button
            className="hub-hero-cta"
            type="primary"
            icon={<DownloadOutlined />}
            loading={downloading === latestRow.version}
            onClick={() => props.onDownload(latestRow)}
          >
            {t('Download latest')}
          </Button>
        )}
      </div>

      {/* ---------- Publisher / numbers / dates: one strip instead of four full-width rows ---------- */}
      <div className="hub-meta">
        <div className="hub-meta-item">
          <span className="k">{t('Publisher')}</span>
          <span className="v" title={hubOwnerLabel(detail.owner, t)}>
            {hubOwnerLabel(detail.owner, t)}
          </span>
        </div>
        <div className="hub-meta-item">
          <span className="k">{t('Total downloads')}</span>
          <span className="v">{t('{count} downloads', { count: detail.downloads.toLocaleString() })}</span>
        </div>
        <div className="hub-meta-item">
          <span className="k">{t('First published')}</span>
          <span className="v" title={fmtTime(detail.created_at)}>
            {fmtTime(detail.created_at)}
          </span>
        </div>
        <div className="hub-meta-item">
          <span className="k">{t('Last updated')}</span>
          <span className="v" title={fmtTime(detail.updated_at)}>
            {fmtTime(detail.updated_at)}
          </span>
        </div>
      </div>

      {install && (
        <div className="soft-panel hub-install">
          <b>{t('Your install:')}</b>{' '}
          {t('Version {version} · {state}', {
            version: install.version,
            state: install.enabled ? t('Enabled') : t('Disabled'),
          })}
          {install.data_rev > 0
            ? ` · ${t('plugin data revision {rev} (updated {time})', {
                rev: install.data_rev,
                time: fmtTime(install.data_updated_at),
              })}`
            : ''}
        </div>
      )}

      {/* ---------- Versions: the only action surface ---------- */}
      <Card
        size="small"
        className="hub-section"
        title={t('Version history')}
        extra={
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            {t('{count} versions', { count: detail.versions.length })}
          </Typography.Text>
        }
      >
        <Table<HubVersionRow>
          className="hub-versions"
          size="small"
          rowKey="version"
          tableLayout="fixed"
          dataSource={detail.versions}
          pagination={false}
          locale={{ emptyText: t('This plugin has no downloadable version yet') }}
          columns={[
            {
              title: (
                <Space size={2}>
                  {t('Version')}
                  <HelpTip title={t('The latest published version is the blue tag; other versions are neutral.')} />
                </Space>
              ),
              dataIndex: 'version',
              width: 104,
              render: (v: string, row) => {
                const isLatest = row.version === detail.latest_version
                const note = row.changelog || t('No changelog provided')
                // The latest version is marked by tag colour only; the tooltip spells it out.
                return (
                  <Tooltip title={isLatest ? `${t('Latest')} · ${note}` : note}>
                    <Tag color={isLatest ? 'blue' : 'default'} style={{ marginInlineEnd: 0 }}>
                      {v}
                    </Tag>
                  </Tooltip>
                )
              },
            },
            {
              title: t('Status'),
              dataIndex: 'status',
              width: 118,
              render: (v: HubVersionStatus | undefined) => versionStatusTag(v, t),
            },
            {
              title: t('Size'),
              dataIndex: 'size',
              width: 76,
              render: (v: number) => fmtBytes(v),
            },
            {
              title: (
                <Space size={2}>
                  {t('Checksum')}
                  <HelpTip
                    title={t('First 12 characters of the package SHA-256. After download the client verifies the full value and refuses to install a package that does not match.')}
                  />
                </Space>
              ),
              dataIndex: 'sha256',
              width: 110,
              render: (v: string) => (
                <Tooltip title={v}>
                  <span className="table-id">{v.slice(0, 12)}</span>
                </Tooltip>
              ),
            },
            {
              title: t('Downloads'),
              dataIndex: 'downloads',
              width: 72,
              render: (v: number) => v.toLocaleString(),
            },
            {
              title: t('Published'),
              dataIndex: 'published_at',
              width: 96,
              render: (v: string | null) =>
                v ? (
                  <Tooltip title={fmtTime(v)}>
                    <span>{fmtRelative(v)}</span>
                  </Tooltip>
                ) : (
                  '—'
                ),
            },
            {
              title: (
                <Space size={2}>
                  {t('Actions')}
                  <HelpTip
                    title={t('Download icon: the installable package; code icon: the source of versions that shipped one; trash icon: remove a version (publisher or admin only).')}
                  />
                </Space>
              ),
              width: 118,
              render: (_, row) => (
                <div className="hub-row-actions">
                  <Tooltip title={t('Download package')}>
                    <Button
                      size="small"
                      type="text"
                      icon={<DownloadOutlined />}
                      aria-label={t('Download package')}
                      // Keep the blue accent only while the action is available: a disabled
                      // button must look disabled, not like a live primary action.
                      style={row.status === 'pending' ? undefined : { color: 'var(--primary)' }}
                      loading={downloading === row.version}
                      // `pending` means the package body has not been uploaded yet
                      disabled={row.status === 'pending'}
                      onClick={() => props.onDownload(row)}
                    />
                  </Tooltip>
                  {row.has_source && (
                    <Tooltip title={t('Download source code')}>
                      <Button
                        size="small"
                        type="text"
                        icon={<CodeOutlined />}
                        aria-label={t('Download source code')}
                        style={{ color: 'var(--ok)' }}
                        loading={downloadingSource === row.version}
                        onClick={() => props.onDownloadSource(row)}
                      />
                    </Tooltip>
                  )}
                  {canManage && (
                    <Popconfirm
                      title={t('Delete this version?')}
                      description={t('The version disappears from the catalogue and the latest version falls back to the highest remaining one. The package is kept for 30 days before automatic cleanup. To change the content, publish a new version.')}
                      okText={t('Delete')}
                      okButtonProps={{ danger: true }}
                      cancelText={t('Cancel')}
                      onConfirm={() => props.onDeleteVersion(row.version)}
                    >
                      <Button
                        size="small"
                        type="text"
                        danger
                        icon={<DeleteOutlined />}
                        aria-label={t('Delete version {version}', { version: row.version })}
                      />
                    </Popconfirm>
                  )}
                </div>
              ),
            },
          ]}
        />
        {rejectedNotes.length > 0 && (
          <Alert
            className="hub-review-note"
            type="warning"
            showIcon
            message={t('Review feedback')}
            description={
              <Space direction="vertical" size={2}>
                {rejectedNotes.map((v) => (
                  <span key={v.version}>
                    <b>v{v.version}</b> · {v.review_note}
                  </span>
                ))}
              </Space>
            }
          />
        )}
      </Card>

      {/* ---------- Readme: clamped, so it cannot bury the version list ---------- */}
      {readme && (
        <Card
          size="small"
          className="hub-section"
          title={t('Plugin description')}
          extra={
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              {t('Raw text from the publisher; the console does not render rich text')}
            </Typography.Text>
          }
        >
          <div className={`hub-readme${readmeOverflows && !readmeExpanded ? ' is-clamped' : ''}`}>
            <div ref={readmeTextRef}>{readme}</div>
          </div>
          {readmeOverflows && (
            <Button
              className="hub-readme-toggle"
              type="link"
              size="small"
              icon={readmeExpanded ? <UpOutlined /> : <DownOutlined />}
              onClick={() => setReadmeExpanded((v) => !v)}
            >
              {readmeExpanded ? t('Collapse') : t('Expand all')}
            </Button>
          )}
        </Card>
      )}

      <JsonPeek data={detail} label={t('Raw response of the plugin detail API (GET /v1/hub/plugins/{plugin_id})')} />
    </div>
  )
}
