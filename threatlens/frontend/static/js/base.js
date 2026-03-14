/* ThreatLens – base.js: WebSocket + shared utilities */

const TL = {
  ws: null,
  stats: {},
  alertCount: 0,

  init() {
    this.connectWS();
    this.startClock();
  },

  connectWS() {
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    this.ws = new WebSocket(`${proto}://${location.host}/ws/live`);

    this.ws.onopen = () => {
      document.getElementById('engine-dot')?.classList.add('online');
      document.getElementById('engine-status').textContent = 'Engine Online';
    };

    this.ws.onclose = (e) => {
      if (e.code === 1008) {
        window.location.href = '/login';
        return;
      }
      document.getElementById('engine-dot')?.classList.remove('online');
      document.getElementById('engine-dot')?.classList.add('offline');
      document.getElementById('engine-status').textContent = 'Reconnecting…';
      setTimeout(() => this.connectWS(), 3000);
    };

    this.ws.onmessage = (e) => {
      const msg = JSON.parse(e.data);
      this.handleMessage(msg);
    };
  },

  handleMessage(msg) {
    if (msg.type === 'stats' || msg.type === 'init') {
      this.updateTopbar(msg.data);
      if (window.TLDashboard) TLDashboard.onStats(msg.data);
    }
    if (msg.type === 'packet') {
      if (window.TLDashboard) TLDashboard.onPacket(msg.data);
      if (window.TLTraffic)   TLTraffic.onPacket(msg.data);
    }
    if (msg.type === 'alert') {
      this.showToast(msg.data);
      this.alertCount++;
      const el = document.getElementById('alert-count');
      if (el) el.textContent = this.alertCount;
      if (window.TLAlerts) TLAlerts.onAlert(msg.data);
    }
  },

  updateTopbar(stats) {
    const ppsEl     = document.getElementById('top-pps');
    const blockedEl = document.getElementById('top-blocked');
    if (ppsEl)     ppsEl.textContent     = (stats.packets_per_sec || 0).toLocaleString();
    if (blockedEl) blockedEl.textContent = (stats.blocked_count   || 0).toLocaleString();
  },

  showToast(alert) {
    let container = document.querySelector('.toast-container');
    if (!container) {
      container = document.createElement('div');
      container.className = 'toast-container';
      document.body.appendChild(container);
    }
    const cls = (alert.severity || '').toLowerCase();
    const toast = document.createElement('div');
    toast.className = `toast ${cls}`;
    toast.innerHTML = `
      <div class="toast-title"><i class="fa-solid fa-triangle-exclamation"></i> ${alert.type || 'Alert'} – ${alert.severity}</div>
      <div class="toast-body">${alert.description || ''}</div>
    `;
    container.appendChild(toast);
    setTimeout(() => toast.remove(), 6000);
  },

  startClock() {
    const el = document.getElementById('topbar-clock');
    if (!el) return;
    const tick = () => {
      el.textContent = new Date().toUTCString().slice(17, 25) + ' UTC';
    };
    tick();
    setInterval(tick, 1000);
  },

  formatBytes(bytes) {
    if (bytes < 1024)       return bytes + ' B';
    if (bytes < 1048576)    return (bytes / 1024).toFixed(1) + ' KB';
    if (bytes < 1073741824) return (bytes / 1048576).toFixed(1) + ' MB';
    return (bytes / 1073741824).toFixed(2) + ' GB';
  },

  severityBadge(sev) {
    const s = (sev || 'low').toLowerCase();
    return `<span class="badge badge-${s}">${sev}</span>`;
  },

  blockedBadge(blocked) {
    return blocked
      ? '<span class="badge badge-blocked">BLOCKED</span>'
      : '<span class="badge badge-allowed">ALLOWED</span>';
  },
};

document.addEventListener('DOMContentLoaded', () => TL.init());
