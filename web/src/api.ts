let authHeader = '';

export function setAuth(username: string, password: string) {
  authHeader = 'Basic ' + btoa(username + ':' + password);
  sessionStorage.setItem('auth', authHeader);
}

export function loadAuth(): boolean {
  authHeader = sessionStorage.getItem('auth') || '';
  return !!authHeader;
}

export function clearAuth() {
  authHeader = '';
  sessionStorage.removeItem('auth');
}

async function request(path: string, opts: any = {}) {
  const headers: Record<string, string> = { 'Content-Type': 'application/json', ...opts.headers };
  if (authHeader) headers['Authorization'] = authHeader;

  const res = await fetch('/api' + path, { ...opts, headers });

  if (res.status === 401) {
    clearAuth();
    throw new Error('Session expired — please login again');
  }
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(err.error || res.statusText);
  }
  return res.json();
}

// Login via POST /api/login — validates against database
export async function testAuth(username: string, password: string) {
  const res = await fetch('/api/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });
  if (res.status === 401) throw new Error('Invalid username or password');
  if (!res.ok) throw new Error('Server error');
  setAuth(username, password);
  return true;
}

export const api = {
  getStats: () => request('/stats'),
  getHealth: () => request('/health'),

  listAccounts: (role?: string) => request('/accounts' + (role ? `?role=${role}` : '')),
  getAccount: (id: number) => request(`/accounts/${id}`),
  // Role is auto-determined by the panel's database role — no need to specify
  createAccount: (token: string, role?: string) => request('/accounts', { method: 'POST', body: JSON.stringify({ token, role: role || '' }) }),
  updateAccount: (id: number, data: any) => request(`/accounts/${id}`, { method: 'PATCH', body: JSON.stringify(data) }),
  deleteAccount: (id: number) => request(`/accounts/${id}`, { method: 'DELETE' }),
  refreshAccount: (id: number) => request(`/accounts/${id}/info`, { method: 'POST' }),
  syncAllAccounts: () => request('/accounts/sync-all', { method: 'POST' }),

  // Remote server proxy (client → Clever Cloud server)
  remoteServerURL: () => request('/remote/server-url'),
  remoteSyncAll: () => request('/remote/sync-all', { method: 'POST' }),
  remoteListAccounts: () => request('/remote/accounts'),
  remoteCreateAccount: (token: string, role: string) => request('/remote/accounts/create', { method: 'POST', body: JSON.stringify({ token, role }) }),
  remoteSyncPull: (since?: number) => request(`/remote/sync/pull?since=${since || 0}`),
  remoteSyncPush: (events: any[]) => request('/remote/sync/push', { method: 'POST', body: JSON.stringify({ events }) }),
  remoteSyncPushAccounts: () => request('/remote/sync/push-accounts', { method: 'POST' }),
  remotePushSingleAccount: (id: number) => request(`/remote/accounts/${id}/push`, { method: 'POST' }),
  remotePushSinglePairing: (id: number) => request(`/remote/pairings/${id}/push`, { method: 'POST' }),
  remotePushAllPairings: () => request('/remote/sync/push-pairings', { method: 'POST' }),
  remotePullAccounts: () => request('/remote/pull-accounts', { method: 'POST' }),
  remoteDBBackup: () => request('/remote/db/backup'),
  remoteDBRestore: (data: any) => request('/remote/db/restore', { method: 'POST', body: JSON.stringify(data) }),
  remoteSyncFromServer: () => request('/remote/sync-from-server', { method: 'POST' }),

  listPairings: (ownerID?: string) => request('/pairings' + (ownerID ? `?owner_id=${ownerID}` : '')),
  createPairing: (clientId: number, serverId: number, ownerID?: string) => request('/pairings', { method: 'POST', body: JSON.stringify({ client_account_id: clientId, server_account_id: serverId, owner_id: ownerID || '' }) }),
  deletePairing: (id: number) => request(`/pairings/${id}`, { method: 'DELETE' }),
  autoPair: (ownerID?: string) => request('/pairings/auto', { method: 'POST', body: JSON.stringify({ owner_id: ownerID || '' }) }),
  availableServers: (ownerID?: string) => request('/accounts/available-servers' + (ownerID ? `?owner_id=${ownerID}` : '')),

  getActive: () => request('/connections/active'),
  getHistory: (limit?: number) => request(`/connections/history?limit=${limit || 50}`),

  // Force end calls from admin panel
  forceEndCall: (serverAccountId: number) => request(`/connections/end/${serverAccountId}`, { method: 'POST' }),
  forceEndAllCalls: () => request('/connections/end-all', { method: 'POST' }),

  getEvents: (since?: number) => request(`/events?since=${since || 0}`),
  getGuide: () => request('/guide'),

  // Sync API
  syncPull: (since?: number) => request(`/sync/pull?since=${since || 0}`),
  syncPush: (events: any[]) => request('/sync/push', { method: 'POST', body: JSON.stringify({ events }) }),
  syncStatus: () => request('/sync/status'),
  syncSnapshot: () => request('/sync/snapshot'),

  // Bale/Soroush OTP Login — role is auto-determined
  baleLoginStart: (phone: string, provider?: string) => request('/bale/login/start', { method: 'POST', body: JSON.stringify({ phone, provider: provider || 'bale' }) }),
  baleLoginVerify: (phone: string, code: string, provider?: string) => request('/bale/login/verify', { method: 'POST', body: JSON.stringify({ phone, code, provider: provider || 'bale' }) }),

  // Tunnel Controls
  tunnelStart: () => request('/tunnel/start', { method: 'POST' }),
  tunnelStop: () => request('/tunnel/stop', { method: 'POST' }),
  tunnelStatus: () => request('/tunnel/status'),
  tunnelForceEndCall: () => request('/tunnel/force-end-call', { method: 'POST' }),

  // Client Identity
  getClientID: () => request('/client-id'),

  // Web Terminal
  terminalInfo: () => request('/terminal/info'),

  // Backup & Restore
  dbBackup: () => request('/db/backup'),
  dbRestore: (data: any) => request('/db/restore', { method: 'POST', body: JSON.stringify(data) }),

  // Logs
  getLogs: (limit?: number, level?: string, component?: string) => {
    const params = new URLSearchParams();
    if (limit) params.set('limit', String(limit));
    if (level) params.set('level', level);
    if (component) params.set('component', component);
    return request(`/logs?${params.toString()}`);
  },
  getLogFiles: () => request('/logs/files'),
  getLogDownloadURL: (file: string): string => {
    return `/api/logs/download?file=${encodeURIComponent(file)}`;
  },
};

// createLogStream creates a WebSocket connection for live log streaming.
// Returns the WebSocket instance. The caller is responsible for closing it.
export function createLogStream(opts?: { level?: string; component?: string }): WebSocket {
  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const params = new URLSearchParams();
  if (opts?.level) params.set('level', opts.level);
  if (opts?.component) params.set('component', opts.component);

  // Encode auth into query for WebSocket (same pattern as terminal)
  const auth = sessionStorage.getItem('auth') || '';
  if (auth) params.set('auth', auth);

  const url = `${proto}//${window.location.host}/api/logs/ws?${params.toString()}`;
  return new WebSocket(url);
}

