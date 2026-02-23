const tg = window.Telegram && window.Telegram.WebApp;

if (!tg || !tg.initData) {
    document.getElementById("unauthorized").style.display = "block";
    document.getElementById("loading").style.display = "none";
} else {
    tg.ready();
    tg.expand();
    try {
        tg.setHeaderColor("#161617");
        tg.setBackgroundColor("#161617");
    } catch (e) {}

    const initData = tg.initData;
    let statusData = null;
    let groupsData = null;
    let dnsData = null;
    let usersData = null;
    let meData = null;
    let groupsLoaded = false;
    let dnsLoaded = false;
    let usersLoaded = false;
    let currentConfigText = "";
    let currentConfigName = "";
    let deleteCallback = null;
    let editingPeerName = null;
    let peerEditDisabled = false;
    let editingSecretHex = null;

    // Modal toggle state
    let upstreamDefaultOn = false;
    let upstreamHealthOn = false;

    function haptic(type, val) {
        try {
            if (type === "selection") tg.HapticFeedback.selectionChanged();
            else if (type === "impact")
                tg.HapticFeedback.impactOccurred(val || "light");
            else if (type === "notification")
                tg.HapticFeedback.notificationOccurred(val || "success");
        } catch (e) {}
    }

    function isAdmin() {
        return meData && meData.role === "admin";
    }

    // --- API ---
    function api(method, path, body) {
        const opts = {
            method,
            headers: {
                "X-Telegram-Init-Data": initData,
                "Content-Type": "application/json",
            },
        };
        if (body) opts.body = JSON.stringify(body);
        return fetch(path, opts).then((r) => {
            if (r.status === 403) {
                document.getElementById("app").style.display = "none";
                document.getElementById("forbidden").style.display = "block";
                return Promise.reject(new Error("forbidden"));
            }
            return r.json();
        });
    }

    // --- Helpers ---
    function formatBytes(b) {
        if (b >= 1073741824) return (b / 1073741824).toFixed(1) + " GB";
        if (b >= 1048576) return (b / 1048576).toFixed(1) + " MB";
        if (b >= 1024) return (b / 1024).toFixed(1) + " KB";
        return b + " B";
    }

    function formatDuration(sec) {
        const d = Math.floor(sec / 86400);
        const h = Math.floor((sec % 86400) / 3600);
        const m = Math.floor((sec % 3600) / 60);
        if (d > 0) return d + "d " + h + "h " + m + "m";
        if (h > 0) return h + "h " + m + "m";
        return m + "m";
    }

    function timeAgo(unix) {
        if (!unix || unix <= 0) return "never";
        const sec = Math.floor(Date.now() / 1000) - unix;
        if (sec < 60) return sec + "s ago";
        if (sec < 3600) return Math.floor(sec / 60) + "m ago";
        if (sec < 86400) return Math.floor(sec / 3600) + "h ago";
        return Math.floor(sec / 86400) + "d ago";
    }

    function peerStatusClass(unix) {
        if (!unix || unix <= 0) return "inactive";
        const sec = Math.floor(Date.now() / 1000) - unix;
        if (sec < 180) return "active";
        return "inactive";
    }

    function truncSecret(s) {
        let d = s;
        if (d.length === 34 && (d.startsWith("dd") || d.startsWith("ee")))
            d = d.slice(2);
        return d.length > 8 ? d.slice(0, 8) + "…" : d;
    }

    function secretType(hex) {
        if (hex.startsWith("ee")) return "ee";
        if (hex.startsWith("dd")) return "dd";
        return "default";
    }

    function escapeHtml(s) {
        const d = document.createElement("div");
        d.textContent = s;
        return d.innerHTML;
    }

    // --- Toast ---
    function showToast(message) {
        const t = document.getElementById("toast");
        document.getElementById("toast-message").textContent = message;
        t.classList.add("show");
        setTimeout(() => t.classList.remove("show"), 2000);
    }

    // --- Tab Navigation ---
    function switchTab(page) {
        haptic("selection");
        document
            .querySelectorAll(".page")
            .forEach((p) => p.classList.remove("active"));
        document
            .querySelectorAll(".tab-item")
            .forEach((t) => t.classList.remove("active"));
        const pageEl = document.getElementById("page-" + page);
        if (pageEl) pageEl.classList.add("active");
        const tabEl = document.querySelector(
            '.tab-item[data-page="' + page + '"]',
        );
        if (tabEl) tabEl.classList.add("active");

        if (page === "upstreams" && !groupsLoaded) refreshGroups();
        if (page === "dns" && !dnsLoaded) refreshDNS();
        if (page === "users" && !usersLoaded) refreshUsers();

        try {
            sessionStorage.setItem("activeTab", page);
        } catch (e) {}
    }

    // --- Refresh Functions ---
    function refresh() {
        api("GET", "/api/status").then((d) => {
            statusData = d;
            renderPeers();
            renderUpstreams();
            renderProxies();
            renderMTProxy();
            document.getElementById("uptime").textContent =
                "⏱ " + formatDuration(d.daemon.uptime_seconds);
        });
    }

    function refreshGroups() {
        api("GET", "/api/groups").then((d) => {
            groupsData = d;
            groupsLoaded = true;
            renderGroups();
        });
    }

    function refreshDNS() {
        api("GET", "/api/dns").then((d) => {
            dnsData = d;
            dnsLoaded = true;
            renderDNS();
        });
    }

    function refreshUsers() {
        api("GET", "/api/users").then((d) => {
            usersData = d;
            usersLoaded = true;
            renderUsers();
        });
    }

    // --- Render: Peers ---
    function renderPeers() {
        if (!statusData) return;
        const peers = statusData.peers || [];
        const el = document.getElementById("peer-list");
        const now = Math.floor(Date.now() / 1000);
        const connected = peers.filter(
            (p) =>
                p.last_handshake_unix > 0 && now - p.last_handshake_unix < 180,
        ).length;

        document.getElementById("wg-stat-total").textContent = peers.length;
        document.getElementById("wg-stat-active").textContent = connected;

        if (peers.length === 0) {
            el.innerHTML = '<div class="empty-state">No peers configured</div>';
            return;
        }

        el.innerHTML = peers
            .map((p) => {
                const name = p.name || p.public_key.slice(0, 8) + "...";
                const status = peerStatusClass(p.last_handshake_unix);
                const esc = escapeHtml(name);
                const escapedName = name.replace(/'/g, "\\'");
                return (
                    '<div class="list-item">' +
                    '<div class="item-icon wg-peer"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg></div>' +
                    '<div class="item-content">' +
                    '<div class="item-title">' +
                    esc +
                    "</div>" +
                    '<div class="item-subtitle">' +
                    '<span class="status-badge ' +
                    status +
                    '">' +
                    (status === "active" ? "Online" : "Offline") +
                    "</span>" +
                    (p.disabled
                        ? ' <span class="status-badge inactive">disabled</span>'
                        : "") +
                    (p.last_handshake_unix > 0
                        ? " • " + timeAgo(p.last_handshake_unix)
                        : "") +
                    "</div></div>" +
                    '<div class="item-action">' +
                    '<div class="toggle-switch ' +
                    (p.disabled ? "" : "active") +
                    '" onclick="togglePeer(\'' +
                    escapedName +
                    "'," +
                    p.disabled +
                    ',event)"><div class="toggle-knob"></div></div>' +
                    '<button class="action-icon-btn" onclick="openPeerEditModal(\'' +
                    escapedName +
                    '\')" title="Edit"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg></button>' +
                    '<button class="action-icon-btn" onclick="showPeerConf(\'' +
                    escapedName +
                    '\')" title="Config"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg></button>' +
                    '<button class="action-icon-btn" onclick="showPeerQR(\'' +
                    escapedName +
                    '\')" title="QR"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg></button>' +
                    '<button class="delete-btn" onclick="promptDelete(\'' +
                    escapedName +
                    '\',\'peer\')" title="Delete"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg></button>' +
                    "</div></div>"
                );
            })
            .join("");
    }

    // --- Render: Upstreams ---
    function renderUpstreams() {
        if (!statusData) return;
        const ups = statusData.upstreams || [];
        const el = document.getElementById("upstream-list");

        document.getElementById("upstream-stat-total").textContent = ups.length;
        document.getElementById("upstream-stat-active").textContent =
            ups.filter((u) => u.state === "healthy").length;

        if (ups.length === 0) {
            el.innerHTML =
                '<div class="empty-state">No upstreams configured</div>';
            return;
        }

        el.innerHTML = ups
            .map((u) => {
                const iconClass =
                    u.type === "outline"
                        ? "item-icon outline"
                        : "item-icon amnezia";
                const healthClass =
                    u.state === "healthy"
                        ? "ok"
                        : u.state === "degraded"
                          ? "checking"
                          : "error";
                const healthText =
                    u.state === "healthy"
                        ? "Healthy"
                        : u.state === "degraded"
                          ? "Degraded"
                          : u.state || "Unknown";
                const badges = [];
                if (u.default) badges.push("default");
                if (!u.enabled) badges.push("disabled");
                const badgeHtml = badges
                    .map(
                        (b) =>
                            '<span class="status-badge inactive">' +
                            b +
                            "</span>",
                    )
                    .join(" ");
                const esc = escapeHtml(u.name);
                const escapedName = u.name.replace(/'/g, "\\'");
                return (
                    '<div class="list-item">' +
                    '<div class="' +
                    iconClass +
                    '"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg></div>' +
                    '<div class="item-content">' +
                    '<div class="item-title">' +
                    esc +
                    "</div>" +
                    '<div class="item-subtitle">' +
                    u.type.toUpperCase() +
                    " • " +
                    '<span class="health-indicator"><span class="health-dot ' +
                    healthClass +
                    '"></span>' +
                    healthText +
                    "</span>" +
                    " " +
                    badgeHtml +
                    " • ↓" +
                    formatBytes(u.rx_bytes) +
                    " ↑" +
                    formatBytes(u.tx_bytes) +
                    "</div></div>" +
                    (isAdmin()
                        ? '<div class="item-action">' +
                          '<div class="toggle-switch ' +
                          (u.enabled ? "active" : "") +
                          '" onclick="toggleUpstream(\'' +
                          escapedName +
                          "'," +
                          !u.enabled +
                          ',event)"><div class="toggle-knob"></div></div>' +
                          '<button class="delete-btn" onclick="promptDelete(\'' +
                          escapedName +
                          '\',\'upstream\')"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg></button>' +
                          "</div>"
                        : "") +
                    "</div>"
                );
            })
            .join("");
    }

    // --- Render: Groups ---
    function renderGroups() {
        const el = document.getElementById("upstream-group-list");
        if (!groupsData || groupsData.length === 0) {
            el.innerHTML = '<div class="empty-state">No groups found</div>';
            return;
        }
        el.innerHTML = groupsData
            .map((g) => {
                const memberNames = (g.members || [])
                    .map((m) => m.name)
                    .join(", ");
                const count = (g.members || []).length;
                const escapedName = g.name.replace(/'/g, "\\'");
                return (
                    '<div class="list-item">' +
                    '<div class="item-icon group"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg></div>' +
                    '<div class="item-content">' +
                    '<div class="item-title">' +
                    escapeHtml(g.name) +
                    "</div>" +
                    '<div class="item-subtitle">' +
                    count +
                    " member" +
                    (count !== 1 ? "s" : "") +
                    (memberNames
                        ? " • " +
                          escapeHtml(memberNames.substring(0, 40)) +
                          (memberNames.length > 40 ? "…" : "")
                        : "") +
                    "</div></div>" +
                    (isAdmin()
                        ? '<div class="item-action"><button class="delete-btn" onclick="promptDelete(\'' +
                          escapedName +
                          '\',\'group\')"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg></button></div>'
                        : "") +
                    "</div>"
                );
            })
            .join("");
    }

    // --- Render: Proxies ---
    function renderProxies() {
        if (!statusData) return;
        const proxies = statusData.proxies || [];
        const el = document.getElementById("proxy-list");

        document.getElementById("proxy-stat-total").textContent =
            proxies.length;
        const types = [...new Set(proxies.map((p) => p.type))];
        document.getElementById("proxy-stat-types").textContent =
            types.length > 0 ? types.join(", ").toUpperCase() : "—";

        if (proxies.length === 0) {
            el.innerHTML =
                '<div class="empty-state">No proxy servers configured</div>';
            return;
        }

        el.innerHTML = proxies
            .map((p) => {
                const iconClass =
                    p.type === "socks5" ? "item-icon socks" : "item-icon http";
                const escapedName = p.name.replace(/'/g, "\\'");
                return (
                    '<div class="list-item">' +
                    '<div class="' +
                    iconClass +
                    '"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg></div>' +
                    '<div class="item-content">' +
                    '<div class="item-title">' +
                    escapeHtml(p.name) +
                    "</div>" +
                    '<div class="item-subtitle">' +
                    p.type.toUpperCase() +
                    " • " +
                    escapeHtml(p.listen) +
                    (p.has_auth ? " • 🔑" : "") +
                    (p.upstream_group ? ' • ↗ ' + escapeHtml(p.upstream_group) : '') +
                    "</div></div>" +
                    '<div class="item-action">' +
                    (p.link
                        ? '<button class="copy-link-btn" onclick="copyText(\'' +
                          p.link.replace(/'/g, "\\'") +
                          "',event)\">Copy</button>"
                        : "") +
                    (isAdmin()
                        ? '<button class="delete-btn" onclick="promptDelete(\'' +
                          escapedName +
                          '\',\'proxy\')"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg></button>'
                        : "") +
                    "</div></div>"
                );
            })
            .join("");
    }

    // --- Render: DNS ---
    function renderDNS() {
        if (!dnsData) return;

        // Status
        const badge = document.getElementById("dns-status-badge");
        const text = document.getElementById("dns-status-text");
        if (dnsData.enabled) {
            badge.textContent = "ON";
            badge.className = "status-badge active";
            text.textContent =
                "Listening on " +
                (dnsData.listen || "—") +
                " → " +
                (dnsData.upstream || "—");
        } else {
            badge.textContent = "OFF";
            badge.className = "status-badge inactive";
            text.textContent = "Disabled";
        }

        // Records
        const recEl = document.getElementById("dns-record-list");
        const records = dnsData.records || [];
        if (records.length === 0) {
            recEl.innerHTML = '<div class="empty-state">No DNS records</div>';
        } else {
            recEl.innerHTML = records
                .map((r) => {
                    const values = (r.a || []).concat(r.aaaa || []);
                    const escapedName = r.name.replace(/'/g, "\\'");
                    return (
                        '<div class="list-item">' +
                        '<div class="item-icon dns-record"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg></div>' +
                        '<div class="item-content">' +
                        '<div class="item-title">' +
                        escapeHtml(r.name) +
                        "</div>" +
                        '<div class="item-subtitle">' +
                        (r.a && r.a.length ? "A" : "") +
                        (r.aaaa && r.aaaa.length ? " AAAA" : "") +
                        " → " +
                        escapeHtml(values.join(", ")) +
                        " • TTL: " +
                        (r.ttl || 0) +
                        "s</div>" +
                        "</div>" +
                        (isAdmin()
                            ? '<div class="item-action">' +
                              '<button class="action-icon-btn" onclick="editDNSRecord(\'' +
                              escapedName +
                              '\')" title="Edit"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg></button>' +
                              '<button class="delete-btn" onclick="promptDelete(\'' +
                              escapedName +
                              '\',\'dns-record\')"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg></button>' +
                              "</div>"
                            : "") +
                        "</div>"
                    );
                })
                .join("");
        }

        // Rules
        const ruleEl = document.getElementById("dns-rule-list");
        const rules = dnsData.rules || [];
        if (rules.length === 0) {
            ruleEl.innerHTML = '<div class="empty-state">No DNS rules</div>';
        } else {
            ruleEl.innerHTML = rules
                .map((r) => {
                    const actionBadge =
                        r.action === "block"
                            ? '<span class="rule-type-badge block">Block</span>'
                            : '<span class="rule-type-badge upstream">Upstream</span>';
                    const domainCount = (r.domains || []).length;
                    const listCount = (r.lists || []).length;
                    const info = [];
                    if (domainCount > 0)
                        info.push(
                            domainCount +
                                " domain" +
                                (domainCount > 1 ? "s" : ""),
                        );
                    if (listCount > 0)
                        info.push(
                            listCount + " list" + (listCount > 1 ? "s" : ""),
                        );
                    if (r.upstream) info.push("→ " + r.upstream);
                    const escapedName = r.name.replace(/'/g, "\\'");
                    return (
                        '<div class="list-item">' +
                        '<div class="item-icon dns-rule"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg></div>' +
                        '<div class="item-content">' +
                        '<div class="item-title">' +
                        escapeHtml(r.name) +
                        "</div>" +
                        '<div class="item-subtitle">' +
                        actionBadge +
                        " • " +
                        info.join(" • ") +
                        "</div>" +
                        "</div>" +
                        (isAdmin()
                            ? '<div class="item-action"><button class="delete-btn" onclick="promptDelete(\'' +
                              escapedName +
                              '\',\'dns-rule\')"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg></button></div>'
                            : "") +
                        "</div>"
                    );
                })
                .join("");
        }
    }

    // --- Render: Users ---
    function renderUsers() {
        if (!usersData) return;
        const el = document.getElementById("user-list");

        document.getElementById("user-stat-total").textContent =
            usersData.length;
        document.getElementById("user-stat-admin").textContent =
            usersData.filter((u) => u.is_admin).length;

        if (usersData.length === 0) {
            el.innerHTML = '<div class="empty-state">No users</div>';
            return;
        }

        el.innerHTML = usersData
            .map((u) => {
                const displayName =
                    (u.first_name || "") +
                        (u.last_name ? " " + u.last_name : "") ||
                    u.username ||
                    "User " + u.user_id;
                const iconClass = u.is_admin
                    ? "item-icon user"
                    : "item-icon user-guest";
                const roleBadge = u.is_admin
                    ? '<span class="status-badge admin">Admin</span>'
                    : '<span class="status-badge guest">Guest</span>';
                const initial = displayName.charAt(0).toUpperCase();
                const avatarContent = u.photo_url
                    ? '<img src="' +
                      escapeHtml(u.photo_url) +
                      '" alt="' +
                      initial +
                      '">'
                    : initial;
                const canDelete = !u.is_config_admin && isAdmin();
                const canToggleRole = !u.is_config_admin && isAdmin();
                return (
                    '<div class="list-item">' +
                    '<div class="' +
                    iconClass +
                    '"><div class="user-avatar">' +
                    avatarContent +
                    "</div></div>" +
                    '<div class="item-content">' +
                    '<div class="item-title">' +
                    escapeHtml(displayName) +
                    "</div>" +
                    '<div class="item-subtitle">' +
                    (u.username ? "@" + escapeHtml(u.username) + " • " : "") +
                    "ID: " +
                    u.user_id +
                    " • " +
                    roleBadge +
                    (u.is_config_admin
                        ? ' <span class="status-badge inactive">config</span>'
                        : "") +
                    "</div></div>" +
                    '<div class="item-action">' +
                    (canToggleRole
                        ? '<button class="action-icon-btn" onclick="toggleUserRole(' +
                          u.user_id +
                          ",'" +
                          (u.is_admin ? "guest" : "admin") +
                          '\')" title="Toggle role"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg></button>'
                        : "") +
                    (canDelete
                        ? '<button class="delete-btn" onclick="promptDelete(' +
                          u.user_id +
                          ',\'user\')"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg></button>'
                        : "") +
                    "</div></div>"
                );
            })
            .join("");
    }

    // --- Render: MTProxy ---
    function renderMTProxy() {
        if (!statusData) return;
        const mt = statusData.mtproxy;

        if (!mt || !mt.enabled) {
            document.getElementById("mtproxy-stat-secrets").textContent = "0";
            document.getElementById("mtproxy-stat-active").textContent = "0";
            document.getElementById("mtproxy-secret-list").innerHTML =
                '<div class="empty-state">MTProxy not enabled</div>';
            return;
        }

        const secrets = mt.secrets || [];
        const links = mt.links || [];
        document.getElementById("mtproxy-stat-secrets").textContent =
            secrets.length;
        document.getElementById("mtproxy-stat-active").textContent =
            mt.active_connections;

        // Build a map from secret hex to its link
        const linkBySecret = {};
        for (const l of links) {
            linkBySecret[l.secret] = l;
        }

        const secEl = document.getElementById("mtproxy-secret-list");
        if (secrets.length === 0) {
            secEl.innerHTML = '<div class="empty-state">No secrets</div>';
        } else {
            secEl.innerHTML = secrets
                .map((s) => {
                    const link = linkBySecret[s.secret];
                    const displayName = link
                        ? link.name || truncSecret(s.secret)
                        : truncSecret(s.secret);
                    const sType = secretType(s.secret);
                    const typeBadge =
                        sType === "ee"
                            ? '<span class="secret-type-badge ee">EE</span>'
                            : sType === "dd"
                              ? '<span class="secret-type-badge dd">DD</span>'
                              : '<span class="secret-type-badge default">Default</span>';
                    const escapedSecret = s.secret.replace(/'/g, "\\'");
                    const connectBtn = link
                        ? '<button class="action-icon-btn" onclick="openProxyLink(\'' +
                          link.url.replace(/'/g, "\\'") +
                          "',event)\" title=\"Connect\"><svg width=\"20\" height=\"20\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"><path d=\"M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71\"/><path d=\"M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71\"/></svg></button>"
                        : "";
                    const copyBtn = link
                        ? '<button class="action-icon-btn" onclick="copyText(\'' +
                          link.url.replace(/'/g, "\\'") +
                          "',event)\" title=\"Copy\"><svg width=\"20\" height=\"20\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"><rect x=\"9\" y=\"9\" width=\"13\" height=\"13\" rx=\"2\" ry=\"2\"/><path d=\"M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1\"/></svg></button>"
                        : "";
                    return (
                        '<div class="list-item">' +
                        '<div class="item-icon secret-' +
                        sType +
                        '"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg></div>' +
                        '<div class="item-content">' +
                        '<div class="item-title">' +
                        escapeHtml(displayName) +
                        "</div>" +
                        '<div class="item-subtitle">' +
                        typeBadge +
                        (s.upstream_group ? ' • ↗ ' + escapeHtml(s.upstream_group) : '') +
                        "</div></div>" +
                        '<div class="item-action">' +
                        '<button class="action-icon-btn" onclick="openSecretEditModal(\'' +
                        escapedSecret +
                        '\')" title="Edit"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg></button>' +
                        connectBtn +
                        copyBtn +
                        '<button class="delete-btn" onclick="promptDelete(\'' +
                        escapedSecret +
                        '\',\'secret\')"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg></button>' +
                        "</div></div>"
                    );
                })
                .join("");
        }
    }

    // --- Modal Helpers ---
    function openModal(id) {
        haptic("impact");
        document.getElementById(id + "-backdrop").classList.add("open");
        document.getElementById(id + "-sheet").classList.add("open");
    }

    function closeModal(id) {
        document.getElementById(id + "-backdrop").classList.remove("open");
        document.getElementById(id + "-sheet").classList.remove("open");
    }

    // --- Peers ---
    window.openPeerModal = function () {
        openModal("peer-modal");
        document.getElementById("inp-peer-name").value = "";
    };
    window.closePeerModal = function () {
        closeModal("peer-modal");
    };
    window.savePeer = function () {
        const name = document.getElementById("inp-peer-name").value.trim();
        if (!name) {
            haptic("notification", "error");
            return;
        }
        api("POST", "/api/peers", { name }).then((d) => {
            if (d.error) {
                haptic("notification", "error");
                showToast(d.error);
                return;
            }
            haptic("notification", "success");
            showToast("Peer created");
            closePeerModal();
            refresh();
        });
    };

    window.openPeerEditModal = function (name) {
        if (!statusData) return;
        const peer = (statusData.peers || []).find((p) => p.name === name);
        if (!peer) return;
        editingPeerName = name;
        peerEditDisabled = peer.disabled;
        document.getElementById("inp-peer-edit-name").value = name;
        document.getElementById("peer-edit-pubkey").textContent =
            peer.public_key;
        document.getElementById("peer-edit-allowed-ips").textContent =
            peer.allowed_ips || "—";
        document.getElementById("peer-edit-stats").innerHTML =
            '<div class="peer-stat-card"><div class="peer-stat-value">↓ ' +
            formatBytes(peer.rx_bytes) +
            '</div><div class="peer-stat-label">Download</div></div>' +
            '<div class="peer-stat-card"><div class="peer-stat-value">↑ ' +
            formatBytes(peer.tx_bytes) +
            '</div><div class="peer-stat-label">Upload</div></div>' +
            '<div class="peer-stat-card"><div class="peer-stat-value">' +
            timeAgo(peer.last_handshake_unix) +
            '</div><div class="peer-stat-label">Handshake</div></div>';

        // Populate upstream group dropdown
        const sel = document.getElementById("inp-peer-edit-upstream-group");
        const allGroups = [...new Set((statusData.upstreams || []).flatMap(u => u.groups || []))];
        sel.innerHTML = '<option value="">Default</option>' +
            allGroups.map(g => '<option value="' + escapeHtml(g) + '"' +
                (peer.upstream_group === g ? ' selected' : '') + '>' + escapeHtml(g) + '</option>'
            ).join('');

        updatePeerEditToggle();
        openModal("peer-edit-modal");
    };
    window.closePeerEditModal = function () {
        closeModal("peer-edit-modal");
        editingPeerName = null;
    };
    window.togglePeerEditDisabled = function () {
        peerEditDisabled = !peerEditDisabled;
        updatePeerEditToggle();
        haptic("selection");
    };
    function updatePeerEditToggle() {
        const el = document.getElementById("peer-edit-enabled-toggle");
        const label = document.getElementById("peer-edit-status-label");
        if (peerEditDisabled) {
            el.classList.remove("active");
            label.textContent = "Disabled";
        } else {
            el.classList.add("active");
            label.textContent = "Enabled";
        }
    }
    window.savePeerEdit = function () {
        if (!editingPeerName) return;
        const newName = document
            .getElementById("inp-peer-edit-name")
            .value.trim();
        if (!newName) {
            haptic("notification", "error");
            showToast("Name cannot be empty");
            return;
        }
        const body = { disabled: peerEditDisabled };
        if (newName !== editingPeerName) {
            body.name = newName;
        }
        const upstreamGroup = document.getElementById("inp-peer-edit-upstream-group").value;
        body.upstream_group = upstreamGroup;
        api(
            "PUT",
            "/api/peers/" + encodeURIComponent(editingPeerName),
            body,
        ).then((d) => {
            if (d.error) {
                haptic("notification", "error");
                showToast(d.error);
                return;
            }
            haptic("notification", "success");
            showToast("Peer updated");
            closePeerEditModal();
            refresh();
        });
    };

    window.showPeerConf = function (name) {
        api("GET", "/api/peers/" + encodeURIComponent(name) + "/conf").then(
            (d) => {
                if (d.error) {
                    showToast(d.error);
                    return;
                }
                currentConfigText = d.config;
                currentConfigName = name;
                document.getElementById("config-modal-title").textContent =
                    name;
                document.getElementById("config-action-btns").style.display = "";
                document.getElementById("config-modal-content").innerHTML =
                    '<pre class="config-pre">' +
                    escapeHtml(d.config) +
                    "</pre>";
                openModal("config-modal");
            },
        );
    };

    window.showPeerQR = function (name) {
        api("GET", "/api/peers/" + encodeURIComponent(name) + "/conf").then(
            (d) => {
                if (d.error) {
                    showToast(d.error);
                    return;
                }
                currentConfigText = d.config;
                document.getElementById("config-modal-title").textContent =
                    name + " QR";
                document.getElementById("config-action-btns").style.display =
                    "none";
                const container = document.getElementById(
                    "config-modal-content",
                );
                container.innerHTML =
                    '<div class="qr-container"><div id="qr-code"></div></div>';
                try {
                    new QRCode(document.getElementById("qr-code"), {
                        text: d.config,
                        width: 256,
                        height: 256,
                        colorDark: "#000000",
                        colorLight: "#ffffff",
                    });
                } catch (e) {
                    container.innerHTML =
                        '<div class="empty-state">QR generation failed</div>';
                }
                openModal("config-modal");
            },
        );
    };

    window.closeConfigModal = function () {
        closeModal("config-modal");
    };
    window.copyConfig = function () {
        navigator.clipboard.writeText(currentConfigText).then(() => {
            haptic("notification", "success");
            showToast("Copied to clipboard");
        });
    };
    window.downloadConfig = function () {
        const blob = new Blob([currentConfigText], { type: "text/plain" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = (currentConfigName || "peer") + ".conf";
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        haptic("notification", "success");
        showToast("Download started");
    };

    // --- Upstreams ---
    window.openUpstreamModal = function () {
        openModal("upstream-modal");
        document.getElementById("upstream-modal-title").textContent =
            "New Upstream";
        document.getElementById("inp-upstream-name").value = "";
        document.getElementById("inp-upstream-transport").value = "";
        upstreamDefaultOn = false;
        upstreamHealthOn = true;
        updateToggle("inp-upstream-default", upstreamDefaultOn);
        updateToggle("inp-upstream-health", upstreamHealthOn);
    };
    window.closeUpstreamModal = function () {
        closeModal("upstream-modal");
    };
    window.toggleUpstreamDefault = function () {
        upstreamDefaultOn = !upstreamDefaultOn;
        updateToggle("inp-upstream-default", upstreamDefaultOn);
        haptic("selection");
    };
    window.toggleUpstreamHealth = function () {
        upstreamHealthOn = !upstreamHealthOn;
        updateToggle("inp-upstream-health", upstreamHealthOn);
        haptic("selection");
    };
    window.saveUpstream = function () {
        const name = document.getElementById("inp-upstream-name").value.trim();
        const transport = document
            .getElementById("inp-upstream-transport")
            .value.trim();
        if (!name || !transport) {
            haptic("notification", "error");
            return;
        }
        api("POST", "/api/upstreams", {
            name,
            type: "outline",
            transport,
            default: upstreamDefaultOn,
            health_check: { enabled: upstreamHealthOn },
        }).then((d) => {
            if (d.error) {
                haptic("notification", "error");
                showToast(d.error);
                return;
            }
            haptic("notification", "success");
            showToast("Upstream added");
            closeUpstreamModal();
            refresh();
            if (groupsLoaded) refreshGroups();
        });
    };

    // --- Groups ---
    window.openGroupModal = function () {
        openModal("group-modal");
        document.getElementById("inp-group-name").value = "";
    };
    window.closeGroupModal = function () {
        closeModal("group-modal");
    };
    window.saveGroup = function () {
        const name = document.getElementById("inp-group-name").value.trim();
        if (!name) {
            haptic("notification", "error");
            return;
        }
        api("POST", "/api/groups", { name }).then((d) => {
            if (d.error) {
                haptic("notification", "error");
                showToast(d.error);
                return;
            }
            haptic("notification", "success");
            showToast("Group created");
            closeGroupModal();
            refreshGroups();
        });
    };

    window.togglePeer = function (name, currentlyDisabled, e) {
        if (e) e.stopPropagation();
        haptic("selection");
        api("PUT", "/api/peers/" + encodeURIComponent(name), {
            disabled: !currentlyDisabled,
        }).then((d) => {
            if (d.error) {
                showToast(d.error);
                return;
            }
            refresh();
        });
    };

    window.toggleUpstream = function (name, enabled, e) {
        if (e) e.stopPropagation();
        haptic("selection");
        api("PUT", "/api/upstreams/" + encodeURIComponent(name), {
            enabled,
        }).then((d) => {
            if (d.error) {
                showToast(d.error);
                return;
            }
            refresh();
        });
    };

    // --- Proxies ---
    window.openProxyModal = function () {
        openModal("proxy-modal");
        document.getElementById("inp-proxy-name").value = "";
        document.getElementById("inp-proxy-listen").value = "";
        document.getElementById("inp-proxy-username").value = "";
        document.getElementById("inp-proxy-password").value = "";
    };
    window.generateProxyPassword = function () {
        const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        const arr = new Uint32Array(16);
        crypto.getRandomValues(arr);
        let pwd = "";
        for (let i = 0; i < 16; i++) pwd += chars[arr[i] % chars.length];
        document.getElementById("inp-proxy-password").value = pwd;
    };
    window.closeProxyModal = function () {
        closeModal("proxy-modal");
    };
    window.saveProxy = function () {
        const type = document.getElementById("inp-proxy-type").value;
        const listen = document.getElementById("inp-proxy-listen").value.trim();
        const name = document.getElementById("inp-proxy-name").value.trim();
        const username = document.getElementById("inp-proxy-username").value.trim();
        const password = document.getElementById("inp-proxy-password").value;
        if (!listen) {
            haptic("notification", "error");
            return;
        }
        api("POST", "/api/proxies", { name, type, listen, username, password }).then((d) => {
            if (d.error) {
                haptic("notification", "error");
                showToast(d.error);
                return;
            }
            haptic("notification", "success");
            showToast("Proxy added");
            closeProxyModal();
            refresh();
        });
    };

    // --- DNS Rules ---
    window.openDNSRuleModal = function () {
        openModal("dns-rule-modal");
        document.getElementById("inp-dns-rule-name").value = "";
        document.getElementById("inp-dns-rule-action").value = "block";
        document.getElementById("inp-dns-rule-upstream").value = "";
        document.getElementById("inp-dns-rule-domains").value = "";
        document.getElementById("inp-dns-rule-list-url").value = "";
        document.getElementById("inp-dns-rule-list-format").value = "domains";
        toggleDNSRuleAction();
    };
    window.closeDNSRuleModal = function () {
        closeModal("dns-rule-modal");
    };
    window.toggleDNSRuleAction = function () {
        const action = document.getElementById("inp-dns-rule-action").value;
        document.getElementById("dns-rule-upstream-group").style.display =
            action === "upstream" ? "" : "none";
    };
    window.saveDNSRule = function () {
        const name = document.getElementById("inp-dns-rule-name").value.trim();
        const action = document.getElementById("inp-dns-rule-action").value;
        const upstream = document
            .getElementById("inp-dns-rule-upstream")
            .value.trim();
        const domainsRaw = document
            .getElementById("inp-dns-rule-domains")
            .value.trim();
        const listUrl = document
            .getElementById("inp-dns-rule-list-url")
            .value.trim();
        const listFormat = document.getElementById(
            "inp-dns-rule-list-format",
        ).value;

        if (!name) {
            haptic("notification", "error");
            return;
        }
        if (action === "upstream" && !upstream) {
            haptic("notification", "error");
            showToast("Upstream required");
            return;
        }

        const domains = domainsRaw
            ? domainsRaw
                  .split(",")
                  .map((d) => d.trim())
                  .filter(Boolean)
            : [];
        const lists = listUrl ? [{ url: listUrl, format: listFormat }] : [];

        if (domains.length === 0 && lists.length === 0) {
            haptic("notification", "error");
            showToast("Add domains or a list URL");
            return;
        }

        api("POST", "/api/dns", {
            name,
            action,
            upstream: action === "upstream" ? upstream : "",
            domains,
            lists,
        }).then((d) => {
            if (d.error) {
                haptic("notification", "error");
                showToast(d.error);
                return;
            }
            haptic("notification", "success");
            showToast('Rule "' + name + '" added');
            closeDNSRuleModal();
            refreshDNS();
        });
    };

    // --- DNS Records ---
    let editingDNSRecord = null;

    window.openDNSRecordModal = function (name, a, aaaa, ttl) {
        openModal("dns-record-modal");
        editingDNSRecord = name || null;
        document.getElementById("dns-record-modal-title").textContent = name
            ? "Edit DNS Record"
            : "New DNS Record";
        const nameInput = document.getElementById("inp-dns-record-name");
        nameInput.value = name || "";
        nameInput.disabled = !!name;
        document.getElementById("inp-dns-record-a").value = (a || []).join(
            ", ",
        );
        document.getElementById("inp-dns-record-aaaa").value = (
            aaaa || []
        ).join(", ");
        document.getElementById("inp-dns-record-ttl").value = ttl || 3600;
    };
    window.closeDNSRecordModal = function () {
        closeModal("dns-record-modal");
        editingDNSRecord = null;
    };

    window.editDNSRecord = function (name) {
        if (!dnsData) return;
        const rec = (dnsData.records || []).find((r) => r.name === name);
        if (!rec) return;
        openDNSRecordModal(name, rec.a, rec.aaaa, rec.ttl);
    };

    window.saveDNSRecord = function () {
        const name = document
            .getElementById("inp-dns-record-name")
            .value.trim();
        const aRaw = document.getElementById("inp-dns-record-a").value.trim();
        const aaaaRaw = document
            .getElementById("inp-dns-record-aaaa")
            .value.trim();
        const ttl =
            parseInt(document.getElementById("inp-dns-record-ttl").value) ||
            3600;

        if (!name) {
            haptic("notification", "error");
            return;
        }

        const a = aRaw
            ? aRaw
                  .split(",")
                  .map((s) => s.trim())
                  .filter(Boolean)
            : [];
        const aaaa = aaaaRaw
            ? aaaaRaw
                  .split(",")
                  .map((s) => s.trim())
                  .filter(Boolean)
            : [];

        if (a.length === 0 && aaaa.length === 0) {
            haptic("notification", "error");
            showToast("Add at least one A or AAAA record");
            return;
        }

        if (editingDNSRecord) {
            api(
                "PUT",
                "/api/dns/records/" + encodeURIComponent(editingDNSRecord),
                { a, aaaa, ttl },
            ).then((d) => {
                if (d.error) {
                    haptic("notification", "error");
                    showToast(d.error);
                    return;
                }
                haptic("notification", "success");
                showToast("Record updated");
                closeDNSRecordModal();
                refreshDNS();
            });
        } else {
            api("POST", "/api/dns/records", { name, a, aaaa, ttl }).then(
                (d) => {
                    if (d.error) {
                        haptic("notification", "error");
                        showToast(d.error);
                        return;
                    }
                    haptic("notification", "success");
                    showToast("Record added");
                    closeDNSRecordModal();
                    refreshDNS();
                },
            );
        }
    };

    // --- Users ---
    window.openUserModal = function () {
        openModal("user-modal");
        document.getElementById("inp-user-input").value = "";
        document.getElementById("inp-user-role").value = "guest";
    };
    window.closeUserModal = function () {
        closeModal("user-modal");
    };
    window.saveUser = function () {
        const user = document.getElementById("inp-user-input").value.trim();
        const role = document.getElementById("inp-user-role").value;
        if (!user) {
            haptic("notification", "error");
            return;
        }
        api("POST", "/api/users", { user, role }).then((d) => {
            if (d.error) {
                haptic("notification", "error");
                showToast(d.error);
                return;
            }
            haptic("notification", "success");
            showToast("User added");
            closeUserModal();
            refreshUsers();
        });
    };

    window.toggleUserRole = function (userId, newRole) {
        haptic("selection");
        api("PUT", "/api/users/" + userId, { role: newRole }).then((d) => {
            if (d.error) {
                showToast(d.error);
                return;
            }
            showToast("Role updated");
            refreshUsers();
        });
    };

    // --- Secrets ---
    window.openSecretModal = function () {
        openModal("secret-modal");
        document.getElementById("inp-secret-type").value = "faketls";
        document.getElementById("inp-secret-comment").value = "";
    };
    window.closeSecretModal = function () {
        closeModal("secret-modal");
    };
    window.saveSecret = function () {
        const type = document.getElementById("inp-secret-type").value;
        const comment = document
            .getElementById("inp-secret-comment")
            .value.trim();
        api("POST", "/api/secrets", { type, comment }).then((d) => {
            if (d.error) {
                haptic("notification", "error");
                showToast(d.error);
                return;
            }
            haptic("notification", "success");
            showToast("Secret created");
            closeSecretModal();
            refresh();
        });
    };

    // --- Secret Edit ---
    window.openSecretEditModal = function (secretHex) {
        if (!statusData || !statusData.mtproxy) return;
        const mt = statusData.mtproxy;
        const s = (mt.secrets || []).find((x) => x.secret === secretHex);
        if (!s) return;
        editingSecretHex = secretHex;

        const links = mt.links || [];
        const link = links.find((l) => l.secret === secretHex);
        const displayName = link ? link.name || "" : "";

        document.getElementById("inp-secret-edit-name").value = displayName;
        document.getElementById("secret-edit-hex").textContent = secretHex;

        const sType = secretType(secretHex);
        const typeLabel =
            sType === "ee"
                ? "FakeTLS (ee)"
                : sType === "dd"
                  ? "Padded (dd)"
                  : "Default";
        document.getElementById("secret-edit-type").textContent = typeLabel;

        // Populate upstream group dropdown
        const sel = document.getElementById('inp-secret-edit-upstream-group');
        const allGroups = [...new Set((statusData.upstreams || []).flatMap(u => u.groups || []))];
        sel.innerHTML = '<option value="">Default</option>' +
            allGroups.map(g => '<option value="' + escapeHtml(g) + '"' +
                (s.upstream_group === g ? ' selected' : '') + '>' + escapeHtml(g) + '</option>'
            ).join('');

        document.getElementById("secret-edit-stats").innerHTML =
            '<div class="peer-stat-card"><div class="peer-stat-value">' +
            s.active_connections +
            '</div><div class="peer-stat-label">Active</div></div>' +
            '<div class="peer-stat-card"><div class="peer-stat-value">↓ ' +
            formatBytes(s.bytes_b2c) +
            '</div><div class="peer-stat-label">Download</div></div>' +
            '<div class="peer-stat-card"><div class="peer-stat-value">↑ ' +
            formatBytes(s.bytes_c2b) +
            '</div><div class="peer-stat-label">Upload</div></div>';
        openModal("secret-edit-modal");
    };
    window.closeSecretEditModal = function () {
        closeModal("secret-edit-modal");
        editingSecretHex = null;
    };
    window.saveSecretEdit = function () {
        if (!editingSecretHex) return;
        const name = document
            .getElementById("inp-secret-edit-name")
            .value.trim();
        const upstreamGroup = document.getElementById('inp-secret-edit-upstream-group').value;

        const namePromise = api(
            "PUT",
            "/api/secrets/" + encodeURIComponent(editingSecretHex) + "/name",
            { name },
        );
        const groupPromise = api(
            "PUT",
            "/api/secrets/" + encodeURIComponent(editingSecretHex),
            { upstream_group: upstreamGroup },
        );

        Promise.all([namePromise, groupPromise]).then(([nd, gd]) => {
            if (nd.error || gd.error) {
                haptic("notification", "error");
                showToast(nd.error || gd.error);
                return;
            }
            haptic("notification", "success");
            showToast("Secret updated");
            closeSecretEditModal();
            refresh();
        });
    };

    // --- Open proxy link ---
    window.openProxyLink = function (url, e) {
        if (e) e.stopPropagation();
        try {
            tg.openTelegramLink(url);
        } catch (err) {
            window.open(url, "_blank");
        }
    };

    // --- Copy ---
    window.copyText = function (text, e) {
        if (e) e.stopPropagation();
        navigator.clipboard.writeText(text).then(() => {
            haptic("notification", "success");
            showToast("Copied!");
        });
    };

    // --- Delete ---
    window.promptDelete = function (id, type) {
        haptic("impact");
        const messages = {
            peer: "Are you sure you want to remove this peer?",
            upstream: "Are you sure you want to remove this upstream?",
            group: "Are you sure you want to remove this group? Upstreams will be unassigned from it.",
            proxy: "Are you sure you want to remove this proxy server?",
            "dns-record": "Are you sure you want to remove this DNS record?",
            "dns-rule": "Are you sure you want to remove this DNS rule?",
            user: "Are you sure you want to remove this user?",
            secret: "Are you sure you want to remove this secret?",
        };
        document.getElementById("alert-message").textContent =
            (messages[type] || "Are you sure?") +
            " This action cannot be undone.";
        document.getElementById("alert-overlay").classList.add("open");

        deleteCallback = function () {
            const endpoints = {
                peer: {
                    method: "DELETE",
                    path: "/api/peers/" + encodeURIComponent(id),
                },
                upstream: {
                    method: "DELETE",
                    path: "/api/upstreams/" + encodeURIComponent(id),
                },
                group: {
                    method: "DELETE",
                    path: "/api/groups/" + encodeURIComponent(id),
                },
                proxy: {
                    method: "DELETE",
                    path: "/api/proxies/" + encodeURIComponent(id),
                },
                "dns-record": {
                    method: "DELETE",
                    path: "/api/dns/records/" + encodeURIComponent(id),
                },
                "dns-rule": {
                    method: "DELETE",
                    path: "/api/dns/rules/" + encodeURIComponent(id),
                },
                user: { method: "DELETE", path: "/api/users/" + id },
                secret: {
                    method: "DELETE",
                    path: "/api/secrets/" + encodeURIComponent(id),
                },
            };
            const ep = endpoints[type];
            if (!ep) return;
            api(ep.method, ep.path).then((d) => {
                if (d.error) {
                    haptic("notification", "error");
                    showToast(d.error);
                    return;
                }
                haptic("notification", "success");
                showToast("Deleted");
                closeAlert();
                if (
                    type === "peer" ||
                    type === "upstream" ||
                    type === "proxy" ||
                    type === "secret"
                )
                    refresh();
                if (type === "dns-record" || type === "dns-rule") refreshDNS();
                if (type === "user") refreshUsers();
                if ((type === "upstream" || type === "group") && groupsLoaded)
                    refreshGroups();
            });
        };
    };

    window.closeAlert = function () {
        document.getElementById("alert-overlay").classList.remove("open");
        deleteCallback = null;
    };

    document.getElementById("confirm-delete-btn").onclick = function () {
        if (deleteCallback) deleteCallback();
    };

    // --- Toggle helper ---
    function updateToggle(id, on) {
        const el = document.getElementById(id);
        if (on) el.classList.add("active");
        else el.classList.remove("active");
    }

    // --- Keep-alive ---
    function ping() {
        const dot = document.getElementById("alive-dot");
        fetch("/api/ping", { method: "GET" })
            .then((r) => (r.ok ? r.json() : Promise.reject()))
            .then(() => {
                dot.className = "alive-dot alive";
            })
            .catch(() => {
                dot.className = "alive-dot dead";
            });
    }
    ping();
    setInterval(ping, 10000);

    // --- Init ---
    api("GET", "/api/me")
        .then((d) => {
            meData = d;
            if (d.role === "admin") document.body.classList.add("is-admin");
            document.getElementById("loading").style.display = "none";
            document.getElementById("app").style.display = "block";
            refresh();
        })
        .catch((err) => {
            document.getElementById("loading").textContent =
                "Failed to load: " + err.message;
        });

    // Restore tab
    try {
        const savedTab = sessionStorage.getItem("activeTab");
        if (savedTab) switchTab(savedTab);
    } catch (e) {}

    // Auto-refresh
    setInterval(refresh, 30000);
}
