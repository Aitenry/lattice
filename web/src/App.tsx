import { Navigate, Route, Routes } from 'react-router-dom'
import { Spin } from 'antd'
import { useAuth } from './auth/AuthProvider'
import AppLayout from './layout/AppLayout'
import LoginPage from './pages/LoginPage'
import OverviewPage from './pages/OverviewPage'
import UsersPage from './pages/UsersPage'
import DevicesPage from './pages/DevicesPage'
import ConversationsPage from './pages/ConversationsPage'
import TopicsPage from './pages/TopicsPage'
import NodesPage from './pages/NodesPage'
import RecordingsPage from './pages/RecordingsPage'
import MessagesPage from './pages/MessagesPage'
import DlqPage from './pages/DlqPage'
import QueuePage from './pages/QueuePage'
import AuditPage from './pages/AuditPage'
import PluginsPage from './pages/PluginsPage'
import PluginHubPage from './pages/PluginHubPage'
import HubDataPage from './pages/HubDataPage'
import HubReviewPage from './pages/HubReviewPage'
import FormatsPage from './pages/FormatsPage'
import ConfigPage from './pages/ConfigPage'
import KeysPage from './pages/KeysPage'

export default function App() {
  const { session, ready } = useAuth()

  if (!ready) {
    return (
      <div className="app-center">
        <Spin size="large" />
      </div>
    )
  }

  if (!session) {
    return (
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="*" element={<Navigate to="/login" replace />} />
      </Routes>
    )
  }

  return (
    <Routes>
      <Route path="/login" element={<Navigate to="/" replace />} />
      <Route element={<AppLayout />}>
        <Route path="/" element={<OverviewPage />} />
        <Route path="/users" element={<UsersPage />} />
        <Route path="/devices" element={<DevicesPage />} />
        <Route path="/nodes" element={<NodesPage />} />
        <Route path="/recordings" element={<RecordingsPage />} />
        <Route path="/conversations" element={<ConversationsPage />} />
        <Route path="/topics" element={<TopicsPage />} />
        <Route path="/messages" element={<MessagesPage />} />
        <Route path="/dlq" element={<DlqPage />} />
        <Route path="/queue" element={<QueuePage />} />
        <Route path="/audit" element={<AuditPage />} />
        <Route path="/hub" element={<PluginHubPage />} />
        <Route path="/hub-data" element={<HubDataPage />} />
        <Route path="/hub-review" element={<HubReviewPage />} />
        <Route path="/plugins" element={<PluginsPage />} />
        <Route path="/formats" element={<FormatsPage />} />
        <Route path="/config" element={<ConfigPage />} />
        <Route path="/keys" element={<KeysPage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  )
}
