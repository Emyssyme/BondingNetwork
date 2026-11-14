/**
 * MySpeedify Frontend Application Controller
 * Real-time WebSocket Telemetry & Canvas Waveform Visualizer
 */

class MySpeedifyApp {
  constructor() {
    this.ws = null;
    this.telemetry = null;
    this.reconnectTimer = null;
    this.isSimulating = false;
    
    // Canvas Chart History Buffers
    this.chartHistoryLength = 60; // 60 data points
    this.chartData = {
      total: new Array(this.chartHistoryLength).fill(0),
      adapters: {} // ip -> array of speeds
    };
    this.adapterCards = new Map();
    this.pendingAdapterToggles = new Map();
    
    this.colorPalette = ['#00f0ff', '#8b5cf6', '#10b981', '#f59e0b', '#ec4899'];

    this.initElements();
    this.initModeSelector();
    this.initSimulationButton();
    this.initCanvas();
    this.fetchInitialStatus();
    this.connectWebSocket();
    this.startAutoPoll();
    this.startCanvasAnimation();
  }

  startAutoPoll() {
    setInterval(() => {
      if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
        this.fetchInitialStatus();
      }
    }, 2000);
  }

  async fetchInitialStatus() {
    try {
      const res = await fetch('/api/status');
      const data = await res.json();
      if (data && !data.error) {
        this.handleTelemetry(data);
      }
    } catch (e) {
      console.error('Failed to fetch initial status:', e);
    }
  }

  initElements() {
    this.elTotalDown = document.getElementById('total-download-speed');
    this.elTotalUp = document.getElementById('total-upload-speed');
    this.elBondedLatency = document.getElementById('bonded-latency');
    this.elTotalRx = document.getElementById('total-rx-data');
    this.elTotalTx = document.getElementById('total-tx-data');
    this.elUptime = document.getElementById('server-uptime');
    this.elAdaptersContainer = document.getElementById('adapters-container');
    this.elAdapterCount = document.getElementById('adapter-count');
    this.elDiagDelivered = document.getElementById('diag-delivered');
    this.elDiagOoo = document.getElementById('diag-ooo');
    this.elDiagDelayed = document.getElementById('diag-delayed');
    this.elDiagDup = document.getElementById('diag-dup');
    this.elDiagBuf = document.getElementById('diag-buf');
    this.elServerEndpoint = document.getElementById('server-endpoint');
    this.elChartLegend = document.getElementById('chart-legend');
    this.btnSim = document.getElementById('btn-toggle-sim');
    this.simBtnText = document.getElementById('sim-btn-text');
    this.btnRefreshAdapters = document.getElementById('btn-refresh-adapters');
    this.elStatusPill = document.getElementById('status-pill');
    this.elConnectionStatus = document.getElementById('connection-status-text');
    if (this.btnRefreshAdapters) {
      this.btnRefreshAdapters.addEventListener('click', () => this.refreshAdapters());
    }
    if (this.elAdaptersContainer) {
      this.elAdaptersContainer.addEventListener('change', (event) => {
        const toggle = event.target;
        if (toggle.matches('.adapter-toggle-input')) {
          this.toggleAdapter(toggle);
        }
      });
    }
  }

  initModeSelector() {
    const modes = ['speed', 'redundant', 'failover'];
    modes.forEach(mode => {
      const btn = document.getElementById(`mode-${mode}`);
      if (btn) {
        btn.addEventListener('click', () => {
          this.switchMode(mode);
        });
      }
    });
  }

  async switchMode(mode) {
    try {
      const res = await fetch('/api/mode', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode })
      });
      const data = await res.json();
      if (data.success) {
        this.updateModeUI(mode);
      }
    } catch (e) {
      console.error('Failed to switch mode:', e);
    }
  }

  async toggleAdapter(toggle) {
    const ip = toggle.dataset.ip;
    const requestedState = toggle.checked;
    this.pendingAdapterToggles.set(ip, requestedState);
    toggle.disabled = true;
    try {
      const res = await fetch('/api/adapter/toggle', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip, enabled: requestedState })
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const result = await res.json();
      if (!result.success) throw new Error('Adapter was not found or could not be changed');
    } catch (e) {
      toggle.checked = !requestedState;
      console.error('Failed to toggle adapter:', e);
    } finally {
      this.pendingAdapterToggles.delete(ip);
      toggle.disabled = false;
    }
  }

  updateModeUI(activeMode) {
    ['speed', 'redundant', 'failover'].forEach(mode => {
      const btn = document.getElementById(`mode-${mode}`);
      if (btn) {
        if (mode === activeMode) {
          btn.classList.add('active');
        } else {
          btn.classList.remove('active');
        }
      }
    });
  }

  initSimulationButton() {
    if (this.btnSim) {
      this.btnSim.addEventListener('click', async () => {
        try {
          const res = await fetch('/api/toggle-simulation', { method: 'POST' });
          const data = await res.json();
          this.isSimulating = data.is_simulating;
          this.updateSimButtonUI();
        } catch (e) {
          console.error('Failed to toggle simulation:', e);
        }
      });
    }
  }

  updateSimButtonUI() {
    if (!this.btnSim) return;
    if (this.isSimulating) {
      this.btnSim.classList.add('active-sim');
      this.simBtnText.textContent = 'Stop Traffic Burst';
      this.btnSim.querySelector('i').className = 'fa-solid fa-stop';
    } else {
      this.btnSim.classList.remove('active-sim');
      this.simBtnText.textContent = 'Simulate Traffic Burst';
      this.btnSim.querySelector('i').className = 'fa-solid fa-play';
    }
  }

  connectWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/telemetry`;

    this.ws = new WebSocket(wsUrl);

    this.ws.onopen = () => {
      console.log('Connected to MySpeedify Daemon');
      if (this.reconnectTimer) {
        clearTimeout(this.reconnectTimer);
        this.reconnectTimer = null;
      }
    };

    this.ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        this.handleTelemetry(data);
      } catch (e) {
        console.error('Error parsing telemetry JSON:', e);
      }
    };

    this.ws.onclose = () => {
      console.warn('WebSocket closed, attempting reconnect in 1.5s...');
      this.reconnectTimer = setTimeout(() => this.connectWebSocket(), 1500);
    };

    this.ws.onerror = (err) => {
      console.error('WebSocket error:', err);
    };
  }

  handleTelemetry(data) {
    this.telemetry = data;
    this.isSimulating = data.dev_mode === true && !!data.is_simulating;
    if (this.btnSim) this.btnSim.hidden = data.dev_mode !== true;
    this.updateSimButtonUI();
    const state = data.state || (data.is_connected ? 'connected' : 'connecting');
    const connected = data.is_connected === true && state !== 'error';
    this.elStatusPill.dataset.state = state;
    this.elConnectionStatus.textContent = connected
      ? 'Connected'
      : (state === 'error' ? 'Error' : (state === 'disconnected' ? 'Disconnected' : 'Connecting'));

    // Top Level Metrics
    this.elTotalDown.textContent = data.download_mbps.toFixed(2);
    this.elTotalUp.textContent = data.upload_mbps.toFixed(2);
    this.elBondedLatency.textContent = data.bonded_latency_ms.toFixed(1);
    this.elTotalRx.innerHTML = `<i class="fa-solid fa-database"></i> ${data.total_rx_mb.toFixed(1)} MB Recv`;
    this.elTotalTx.innerHTML = `<i class="fa-solid fa-database"></i> ${data.total_tx_mb.toFixed(1)} MB Sent`;
    
    // Uptime formatter
    const s = data.uptime_seconds || 0;
    const h = String(Math.floor(s / 3600)).padStart(2, '0');
    const m = String(Math.floor((s % 3600) / 60)).padStart(2, '0');
    const sec = String(s % 60).padStart(2, '0');
    this.elUptime.innerHTML = `<i class="fa-regular fa-clock"></i> ${h}:${m}:${sec}`;

    this.elServerEndpoint.textContent = data.server || '127.0.0.1:51820';
    this.updateModeUI(data.mode);

    // Diagnostics / Reordering Engine
    if (data.reorder_stats) {
      this.elDiagDelivered.textContent = data.reorder_stats.delivered.toLocaleString();
      this.elDiagOoo.textContent = data.reorder_stats.out_of_order.toLocaleString();
      this.elDiagDelayed.textContent = data.reorder_stats.delayed.toLocaleString();
      this.elDiagDup.textContent = data.reorder_stats.duplicates_dropped.toLocaleString();
      this.elDiagBuf.textContent = `${data.reorder_stats.buffered_packets} pkts`;
    }

    // Render Adapters
    this.renderAdapters(data.adapters || []);

    // Update Chart Buffers
    this.updateChartBuffers(data);
  }

  renderAdapters(adapters) {
    this.elAdapterCount.textContent = `${adapters.filter(a => a.enabled).length} Active`;

    if (adapters.length === 0) {
      const empty = document.createElement('div');
      empty.className = 'loading-state';
      empty.textContent = 'No network adapters detected';
      this.elAdaptersContainer.replaceChildren(empty);
      this.adapterCards.clear();
      this.elChartLegend.replaceChildren();
      return;
    }

    const empty = this.elAdaptersContainer.querySelector('.loading-state');
    if (empty) empty.remove();

    const activeIps = new Set(adapters.map(adapter => adapter.ip));
    this.adapterCards.forEach((card, ip) => {
      if (!activeIps.has(ip)) {
        card.element.remove();
        this.adapterCards.delete(ip);
      }
    });

    const legendNodes = document.createDocumentFragment();
    const totalLegend = document.createElement('div');
    totalLegend.className = 'legend-item';
    const totalColor = document.createElement('div');
    totalColor.className = 'legend-color';
    totalColor.style.background = '#ffffff';
    const totalLabel = document.createElement('span');
    totalLabel.textContent = 'Total Bonded';
    totalLegend.append(totalColor, totalLabel);
    legendNodes.append(totalLegend);

    adapters.forEach((adapter, idx) => {
      const color = this.colorPalette[idx % this.colorPalette.length];
      const icon = adapter.is_wifi ? 'fa-wifi' : (adapter.is_cellular ? 'fa-tower-cell' : 'fa-ethernet');
      const typeLabel = adapter.is_wifi ? 'Wi-Fi' : (adapter.is_cellular ? 'Cellular / USB' : 'Ethernet');
      let card = this.adapterCards.get(adapter.ip);
      if (!card) {
        card = this.createAdapterCard(adapter.ip);
        this.adapterCards.set(adapter.ip, card);
      }
      this.updateAdapterCard(card, adapter, color, icon, typeLabel);
      const current = this.elAdaptersContainer.children[idx];
      if (current !== card.element) {
        this.elAdaptersContainer.insertBefore(card.element, current || null);
      }

      const legend = document.createElement('div');
      legend.className = 'legend-item';
      const swatch = document.createElement('div');
      swatch.className = 'legend-color';
      swatch.style.background = color;
      const legendLabel = document.createElement('span');
      legendLabel.textContent = (adapter.name || 'Adapter').split(' ')[0];
      legend.append(swatch, legendLabel);
      legendNodes.append(legend);
    });

    this.elChartLegend.replaceChildren(legendNodes);
  }

  createAdapterCard(ip) {
    const item = document.createElement('div');
    item.className = 'adapter-item';
    item.dataset.ip = ip;

    const header = document.createElement('div');
    header.className = 'adapter-header';
    const titleGroup = document.createElement('div');
    titleGroup.className = 'adapter-title-group';
    const typeIcon = document.createElement('div');
    typeIcon.className = 'adapter-type-icon';
    const iconElement = document.createElement('i');
    typeIcon.append(iconElement);
    const details = document.createElement('div');
    const name = document.createElement('div');
    name.className = 'adapter-name';
    const nameText = document.createElement('span');
    const badge = document.createElement('span');
    badge.className = 'adapter-badge';
    name.append(nameText, badge);
    const description = document.createElement('div');
    description.className = 'adapter-desc';
    const address = document.createElement('div');
    address.className = 'adapter-ip';
    details.append(name, description, address);
    titleGroup.append(typeIcon, details);

    const label = document.createElement('label');
    label.className = 'switch';
    const toggle = document.createElement('input');
    toggle.type = 'checkbox';
    toggle.className = 'adapter-toggle-input';
    toggle.dataset.ip = ip;
    const slider = document.createElement('span');
    slider.className = 'slider';
    label.append(toggle, slider);
    header.append(titleGroup, label);

    const stats = document.createElement('div');
    stats.className = 'adapter-stats-grid';
    const statValues = [];
    const statLabels = ['Speed', 'Latency', 'Loss'];
    for (let index = 0; index < 3; index += 1) {
      const cell = document.createElement('div');
      cell.className = 'stat-cell';
      const labelElement = document.createElement('span');
      labelElement.className = 'stat-cell-lbl';
      labelElement.textContent = statLabels[index];
      const valueElement = document.createElement('span');
      valueElement.className = 'stat-cell-val';
      cell.append(labelElement, valueElement);
      stats.append(cell);
      statValues.push(valueElement);
    }
    item.append(header, stats);
    return { element: item, iconElement, typeIcon, nameText, badge, description, address, toggle, statValues };
  }

  updateAdapterCard(card, adapter, color, icon, typeLabel) {
    const speedTotal = (adapter.download_speed_mbps + adapter.upload_speed_mbps).toFixed(2);
    const pending = this.pendingAdapterToggles.has(adapter.ip);
    card.element.className = `adapter-item ${adapter.enabled ? 'active' : 'disabled'}`;
    card.typeIcon.style.color = color;
    card.iconElement.className = `fa-solid ${icon}`;
    card.nameText.textContent = adapter.name || 'Unknown adapter';
    card.badge.textContent = typeLabel;
    card.description.textContent = adapter.description || '';
    card.description.hidden = !adapter.description;
    card.address.textContent = adapter.ip;
    card.toggle.checked = pending
      ? this.pendingAdapterToggles.get(adapter.ip)
      : adapter.enabled;
    card.toggle.disabled = pending;
    card.statValues[0].textContent = `${speedTotal} Mbps`;
    card.statValues[0].style.color = color;
    card.statValues[1].textContent = `${adapter.latency_ms.toFixed(0)} ms`;
    card.statValues[1].style.color = '';
    card.statValues[2].textContent = `${adapter.loss_pct.toFixed(1)}%`;
    card.statValues[2].style.color = '';
  }

  async refreshAdapters() {
    if (this.btnRefreshAdapters) {
      const icon = this.btnRefreshAdapters.querySelector('i');
      if (icon) icon.classList.add('fa-spin');
    }
    try {
      const resp = await fetch('/api/adapters/refresh', { method: 'POST' });
      const data = await resp.json();
      if (data && data.adapters) {
        this.renderAdapters(data.adapters);
      }
    } catch (err) {
      console.error('Failed to refresh adapters:', err);
    } finally {
      if (this.btnRefreshAdapters) {
        const icon = this.btnRefreshAdapters.querySelector('i');
        if (icon) icon.classList.remove('fa-spin');
      }
    }
  }

  updateChartBuffers(data) {
    const totalSpeed = (data.download_mbps + data.upload_mbps) || 0;
    this.chartData.total.shift();
    this.chartData.total.push(totalSpeed);

    (data.adapters || []).forEach(adapter => {
      if (!this.chartData.adapters[adapter.ip]) {
        this.chartData.adapters[adapter.ip] = new Array(this.chartHistoryLength).fill(0);
      }
      const speed = (adapter.download_speed_mbps + adapter.upload_speed_mbps) || 0;
      this.chartData.adapters[adapter.ip].shift();
      this.chartData.adapters[adapter.ip].push(speed);
    });
  }

  initCanvas() {
    this.canvas = document.getElementById('trafficCanvas');
    this.ctx = this.canvas.getContext('2d');
    
    // Handle High-DPI canvas rendering
    this.resizeCanvas();
    window.addEventListener('resize', () => this.resizeCanvas());
  }

  resizeCanvas() {
    if (!this.canvas) return;
    const rect = this.canvas.getBoundingClientRect();
    const dpr = window.devicePixelRatio || 1;
    this.canvas.width = rect.width * dpr;
    this.canvas.height = rect.height * dpr;
    this.ctx.scale(dpr, dpr);
    this.canvasWidth = rect.width;
    this.canvasHeight = rect.height;
  }

  startCanvasAnimation() {
    const draw = () => {
      this.renderCanvasGraph();
      requestAnimationFrame(draw);
    };
    requestAnimationFrame(draw);
  }

  renderCanvasGraph() {
    if (!this.ctx || !this.canvasWidth) return;
    const ctx = this.ctx;
    const w = this.canvasWidth;
    const h = this.canvasHeight;

    ctx.clearRect(0, 0, w, h);

    // Grid lines
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.04)';
    ctx.lineWidth = 1;
    for (let y = 0; y < h; y += 35) {
      ctx.beginPath();
      ctx.moveTo(0, y);
      ctx.lineTo(w, y);
      ctx.stroke();
    }

    // Determine max scale
    let maxVal = Math.max(10.0, ...this.chartData.total);
    Object.values(this.chartData.adapters).forEach(arr => {
      maxVal = Math.max(maxVal, ...arr);
    });
    maxVal *= 1.25; // Headroom

    // Draw individual adapter lines
    let adapterIndex = 0;
    for (const [ip, values] of Object.entries(this.chartData.adapters)) {
      const color = this.colorPalette[adapterIndex % this.colorPalette.length];
      this.drawSmoothSeries(ctx, values, color, maxVal, w, h, false);
      adapterIndex++;
    }

    // Draw total bonded line with glowing gradient fill
    this.drawSmoothSeries(ctx, this.chartData.total, '#ffffff', maxVal, w, h, true);
  }

  drawSmoothSeries(ctx, dataArr, color, maxVal, w, h, fillGradient = false) {
    if (dataArr.length < 2) return;
    const step = w / (dataArr.length - 1);

    ctx.beginPath();
    const getY = (val) => h - (val / maxVal) * (h - 20) - 10;

    ctx.moveTo(0, getY(dataArr[0]));
    for (let i = 1; i < dataArr.length; i++) {
      const xPrev = (i - 1) * step;
      const yPrev = getY(dataArr[i - 1]);
      const xCurr = i * step;
      const yCurr = getY(dataArr[i]);

      const cx = (xPrev + xCurr) / 2;
      ctx.bezierCurveTo(cx, yPrev, cx, yCurr, xCurr, yCurr);
    }

    ctx.strokeStyle = color;
    ctx.lineWidth = fillGradient ? 2.5 : 1.5;
    ctx.stroke();

    if (fillGradient) {
      ctx.lineTo(w, h);
      ctx.lineTo(0, h);
      ctx.closePath();
      const grad = ctx.createLinearGradient(0, 0, 0, h);
      grad.addColorStop(0, 'rgba(0, 240, 255, 0.25)');
      grad.addColorStop(1, 'rgba(0, 240, 255, 0.0)');
      ctx.fillStyle = grad;
      ctx.fill();
    }
  }
}

document.addEventListener('DOMContentLoaded', () => {
  window.app = new MySpeedifyApp();
});
