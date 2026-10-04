import React from 'react';
import ReactDOM from 'react-dom/client';

function App() {
  return (
    <main style={{ fontFamily: 'system-ui, sans-serif', padding: '2rem', color: '#e2e8f0', background: '#020817' }}>
      <div style={{ maxWidth: '960px', margin: '0 auto' }}>
        <h1>VeriCred Admin</h1>
        <p>Tenant management, credential issuance, revocation and audit is being prepared here.</p>
        <ul>
          <li>Multi-tenant issuer management</li>
          <li>Schema and credential policy controls</li>
          <li>Revocation and status-list overview</li>
          <li>miTch health and trust callbacks</li>
        </ul>
      </div>
    </main>
  );
}

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
