import React from 'react'
import ReactDOM from 'react-dom/client'
import { App as AntApp } from 'antd'
import { BrowserRouter } from 'react-router-dom'
import App from './App'
import { AuthProvider } from './auth/AuthProvider'
import { ThemeModeProvider } from './components/ThemeProvider'
import { I18nProvider } from './i18n'
import './styles.css'

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <I18nProvider>
      <ThemeModeProvider>
        <AntApp>
          <BrowserRouter>
            <AuthProvider>
              <App />
            </AuthProvider>
          </BrowserRouter>
        </AntApp>
      </ThemeModeProvider>
    </I18nProvider>
  </React.StrictMode>,
)
