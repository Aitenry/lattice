import { useEffect, useState } from 'react'
import { errText } from '@/lib/errors'
import { Alert, Button, Card, Form, Input, Space, Tag, Tooltip, Typography, App as AntApp } from 'antd'
import {
  AuditOutlined,
  LockOutlined,
  MoonOutlined,
  SafetyCertificateOutlined,
  SunOutlined,
  UserOutlined,
  WifiOutlined,
} from '@ant-design/icons'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '@/auth/AuthProvider'
import { ApiError, probeReady } from '@/api/http'
import { BRAND } from '@/theme'
import { useThemeMode } from '@/components/ThemeProvider'
import LanguageSwitch from '@/components/LanguageSwitch'
import { useI18n } from '@/i18n'

export default function LoginPage() {
  const { t } = useI18n()
  const { login } = useAuth()
  const nav = useNavigate()
  const { message } = AntApp.useApp()
  const { mode, toggle: toggleTheme } = useThemeMode()
  const [loading, setLoading] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const [node, setNode] = useState<{ ready: boolean; deps: Record<string, string>; version?: string } | null>(null)

  useEffect(() => {
    let alive = true
    probeReady()
      .then((r) => alive && setNode(r))
      .catch(() => alive && setNode(null))
    return () => {
      alive = false
    }
  }, [])

  async function onFinish(values: { username: string; password: string }) {
    setLoading(true)
    setErr(null)
    try {
      await login(values.username, values.password)
      message.success(t('Signed in successfully'))
      nav('/', { replace: true })
    } catch (e) {
      if (e instanceof ApiError && (e.code === 'AUTH_FAIL' || e.status === 401)) {
        setErr(t('Incorrect username or password. Repeated failures may trigger rate limiting; check your credentials and try again.'))
      } else {
        setErr(errText(e))
      }
    } finally {
      setLoading(false)
    }
  }

  const depsOk = node?.ready && Object.values(node.deps ?? {}).every((v) => v === 'ok')

  return (
    <div className="login-shell">
      <aside className="login-aside">
        <div className="brand-line">
          <div className="sider-logo" style={{ width: 34, height: 34, fontSize: 16 }}>
            L
          </div>
          {t(BRAND.fullName)}
        </div>

        <div>
          <h1>
            {t('Every message')}
            <br />
            {t('securely and in order,')} <em>{t('traceably delivered')}</em>
          </h1>
          <p className="lead">
            {t('This is the platform admin console. Use it for daily operations such as watching online scale and investigating delivery failures; compliance actions are recorded here and can be reviewed later.')}
          </p>

          <div className="login-points">
            <div className="login-point">
              <span className="ico">
                <SafetyCertificateOutlined />
              </span>
              <div>
                <div className="login-point-title">{t('End-to-end encryption')}</div>
                <div style={{ opacity: 0.72, marginTop: 2 }}>
                  {t('The server only holds ciphertext, so this console cannot see any message content.')}
                </div>
              </div>
            </div>
            <div className="login-point">
              <span className="ico">
                <WifiOutlined />
              </span>
              <div>
                <div className="login-point-title">{t('Multi-device online and backfill')}</div>
                <div style={{ opacity: 0.72, marginTop: 2 }}>
                  {t('While offline, messages queue by sequence; they are backfilled in order once the device comes online.')}
                </div>
              </div>
            </div>
            <div className="login-point">
              <span className="ico">
                <AuditOutlined />
              </span>
              <div>
                <div className="login-point-title">{t('Every action is recorded')}</div>
                <div style={{ opacity: 0.72, marginTop: 2 }}>
                  {t('Bans, deletions and config changes all require a reason and go into the audit log.')}
                </div>
              </div>
            </div>
          </div>
        </div>

        <div className="login-foot">
          {node?.version ? `${t('Node version {version}', { version: node.version })} · ` : ''}
          {t('Lattice admin console v0.1.1')}
        </div>
      </aside>

      <main className="login-main">
        <div style={{ position: 'absolute', top: 16, right: 60, zIndex: 2 }}>
          <LanguageSwitch size="small" />
        </div>
        <Tooltip title={mode === 'dark' ? t('Switch to light mode') : t('Switch to dark mode')}>
          <Button
            className="login-theme-toggle"
            type="text"
            aria-label={mode === 'dark' ? t('Switch to light mode') : t('Switch to dark mode')}
            data-testid="theme-toggle"
            icon={mode === 'dark' ? <SunOutlined /> : <MoonOutlined />}
            onClick={toggleTheme}
          />
        </Tooltip>
        <div className="login-card">
          <div className="login-card-head">
            <h2>{t('Sign in to the admin console')}</h2>
            <p>{t('Use the account assigned to you by an administrator. Self-registration is not available.')}</p>
          </div>

          <Card>
            {err && <Alert type="error" showIcon message={err} style={{ marginBottom: 16 }} />}

            <Form layout="vertical" onFinish={onFinish} requiredMark={false} size="large">
              <Form.Item
                name="username"
                label={t('Username')}
                rules={[{ required: true, message: t('Enter your username') }]}
              >
                <Input prefix={<UserOutlined />} autoComplete="username" autoFocus placeholder={t('e.g. admin')} />
              </Form.Item>
              <Form.Item
                name="password"
                label={t('Password')}
                rules={[{ required: true, message: t('Enter your password') }]}
              >
                <Input.Password
                  prefix={<LockOutlined />}
                  autoComplete="current-password"
                  placeholder={t('Enter your password')}
                />
              </Form.Item>
              <Button type="primary" htmlType="submit" block size="large" loading={loading}>
                {t('Sign in')}
              </Button>
            </Form>

            <div style={{ marginTop: 16, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <Space size={6}>
                <Tag color={depsOk ? 'green' : node ? 'orange' : 'red'}>
                  {depsOk
                    ? t('Service healthy')
                    : node
                      ? t('Some dependencies degraded')
                      : t('Cannot reach the service')}
                </Tag>
                {!depsOk && node ? (
                  <Tooltip
                    title={Object.entries(node.deps ?? {})
                      .map(([k, v]) => `${k}: ${v}`)
                      .join(' · ')}
                  >
                    <Typography.Text type="secondary" style={{ fontSize: 12, cursor: 'help' }}>
                      {t('View dependency details')}
                    </Typography.Text>
                  </Tooltip>
                ) : null}
              </Space>
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                {t('Sessions last 15 minutes and renew automatically')}
              </Typography.Text>
            </div>
          </Card>

          <Typography.Paragraph type="secondary" style={{ fontSize: 12, marginTop: 14, marginBottom: 0 }}>
            {t('Forgot your password? Ask an administrator to reset it. In development the first administrator is created from the server bootstrap config; see the deployment guide.')}
          </Typography.Paragraph>
        </div>
      </main>
    </div>
  )
}
