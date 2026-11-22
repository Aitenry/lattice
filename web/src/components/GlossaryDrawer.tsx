import { Drawer, Space, Tag, Typography } from 'antd'
import { useI18n } from '@/i18n'

const { Title, Paragraph, Text } = Typography

const CONCEPTS: { term: string; alias?: string; desc: string }[] = [
  {
    term: 'User',
    desc: 'An account that can use the platform. There is no self-registration — only an administrator can create accounts. A suspended account cannot sign in, but its data is kept.',
  },
  {
    term: 'Device',
    alias: 'Terminal / client',
    desc: 'One person can sign in separately on a phone, a computer and the web; each signed-in instance is a "device". Revoking a device signs it out remotely.',
  },
  {
    term: 'Conversation',
    alias: 'Chat / group',
    desc: 'A container for messages. Three kinds: direct message (2 people), group (many people) and broadcast (sent per topic, high volume, no per-message record).',
  },
  {
    term: 'Message',
    desc: 'One encrypted item. The console only stores metadata such as who, in which conversation, when and how large; the server cannot decrypt the content, so content is not viewable here.',
  },
  {
    term: 'Delivery state',
    desc: 'The journey of a message from storage to acknowledgement: persisted → routed to node → delivered to device → acknowledged. Only "acknowledged" proves it was really received.',
  },
  {
    term: 'Delivery failures',
    alias: 'Dead letters',
    desc: 'Messages that still could not be delivered after several retries end up here (for example, the device stayed offline past the retention period). Once confirmed safe, they can be selected and replayed.',
  },
  {
    term: 'Offline queue',
    desc: 'While the recipient is offline, messages queue in order; when it comes online they are backfilled by sequence. Purging the queue discards those pending messages (the messages themselves stay in storage).',
  },
  {
    term: 'Node',
    alias: 'Server instance',
    desc: 'One server in the cluster. Online and connection counts on the dashboard are aggregated per node.',
  },
  {
    term: 'Plugin',
    desc: 'Extends message processing (transcoding, thumbnails, content moderation, ...). A new version can first be rolled out to a small share of traffic ("canary") and rolled back immediately if something goes wrong.',
  },
  {
    term: 'Plugin hub',
    desc: 'Third-party plugin repository for desktop clients: users publish plugin packages, others browse, download and install them; install records and plugin settings follow the account across devices. The platform only stores and distributes packages and does not execute plugin code. Plugins under "Plugins" are server-side format processors — a different thing.',
  },
  {
    term: 'File formats',
    desc: 'A mapping that tells the platform which handler processes which content, e.g. application/json goes to the built-in JSON processor.',
  },
  {
    term: 'Dynamic config',
    desc: 'Parameters such as rate limits and canary ratios that can be adjusted at any time, take effect within seconds and need no restart.',
  },
  {
    term: 'Key',
    desc: 'Keys used to sign login tokens and encrypt data. The console only shows fingerprints and never the private key itself.',
  },
]

export function GlossaryDrawer(props: { open: boolean; onClose: () => void }) {
  const { t } = useI18n()
  return (
    <Drawer open={props.open} onClose={props.onClose} title={t('Guide · Glossary')} width={520}>
      <Paragraph type="secondary" style={{ fontSize: 13 }}>
        {t('This page explains the terms and states you see in the console. If something is still unclear, click the small question mark next to it.')}
      </Paragraph>

      <Title level={5} style={{ marginTop: 20 }}>
        {t('Roles and what they can do')}
      </Title>
      <Space direction="vertical" size={8} style={{ width: '100%' }}>
        <div>
          <Tag color="red">{t('Admin')}</Tag>
          <Text style={{ fontSize: 13 }}>
            {t('Full access: create accounts, change roles and quotas, compliance deletions, publish plugins, change config, rotate keys.')}
          </Text>
        </div>
        <div>
          <Tag color="gold">{t('Ops')}</Tag>
          <Text style={{ fontSize: 13 }}>
            {t('Operational actions: ban/unban, revoke devices, replay delivery failures, purge the offline queue.')}
          </Text>
        </div>
        <div>
          <Tag color="blue">{t('Read-only')}</Tag>
          <Text style={{ fontSize: 13 }}>{t('View only; no action buttons are shown.')}</Text>
        </div>
      </Space>

      <Title level={5} style={{ marginTop: 24 }}>
        {t('Glossary')}
      </Title>
      <Space direction="vertical" size={14} style={{ width: '100%' }}>
        {CONCEPTS.map((c) => (
          <div key={c.term}>
            <Space size={6} align="baseline">
              <Text strong>{t(c.term)}</Text>
              {c.alias ? (
                <Text type="secondary" style={{ fontSize: 12 }}>
                  ({t(c.alias)})
                </Text>
              ) : null}
            </Space>
            <div className="muted" style={{ marginTop: 2 }}>
              {t(c.desc)}
            </div>
          </div>
        ))}
      </Space>

      <Title level={5} style={{ marginTop: 24 }}>
        {t('Common questions')}
      </Title>
      <Space direction="vertical" size={12} style={{ width: '100%' }}>
        <div>
          <Text strong>{t("Why can't I see message content?")}</Text>
          <div className="muted">
            {t('Messages are end-to-end encrypted and the server only holds ciphertext, so decryption is technically impossible. This is by design, not a permission problem.')}
          </div>
        </div>
        <div>
          <Text strong>{t('Why does a role change not take effect immediately?')}</Text>
          <div className="muted">
            {t('Permissions are embedded in the login token, which is valid for 15 minutes. Signing in again applies them immediately; otherwise they apply within 15 minutes.')}
          </div>
        </div>
        <div>
          <Text strong>{t('Why is there no sign-up button?')}</Text>
          <div className="muted">
            {t('The platform does not allow self-registration; new accounts are created by an administrator under "Users".')}
          </div>
        </div>
        <div>
          <Text strong>{t('Why do risky actions require a reason?')}</Text>
          <div className="muted">
            {t('Every action is written to the audit log (kept for 90 days) together with the reason, so it can be reviewed later.')}
          </div>
        </div>
      </Space>
    </Drawer>
  )
}
