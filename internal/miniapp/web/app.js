const tg = window.Telegram && window.Telegram.WebApp;

if (!tg || !tg.initData) {
    document.getElementById("unauthorized").style.display = "block";
    document.getElementById("loading").style.display = "none";
} else {
    tg.ready();
    tg.expand();

    // --- Theme ---
    var THEME_KEY = 'theme-preference';
    var THEMES = ['system', 'light', 'dark'];
    var THEME_ICONS = {
        system: '<svg viewBox="0 0 24 24"><defs><clipPath id="ts"><path d="M24 0v24H0z"/></clipPath></defs><circle cx="12" cy="12" r="9" fill="#dedede"/><circle cx="12" cy="12" r="9" fill="#212121" clip-path="url(#ts)"/><circle cx="12" cy="12" r="9" fill="none" stroke="#888" stroke-width="1.5"/></svg>',
        dark: '<svg viewBox="0 0 24 24"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" fill="currentColor"/></svg>',
        light: '<svg viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="4" fill="currentColor"/><g stroke="currentColor" stroke-width="2" stroke-linecap="round"><line x1="12" y1="2" x2="12" y2="5"/><line x1="12" y1="19" x2="12" y2="22"/><line x1="2" y1="12" x2="5" y2="12"/><line x1="19" y1="12" x2="22" y2="12"/><line x1="4.22" y1="4.22" x2="6.34" y2="6.34"/><line x1="17.66" y1="17.66" x2="19.78" y2="19.78"/><line x1="4.22" y1="19.78" x2="6.34" y2="17.66"/><line x1="17.66" y1="6.34" x2="19.78" y2="4.22"/></g></svg>'
    };

    function getStoredTheme() {
        try { return localStorage.getItem(THEME_KEY) || 'system'; } catch (e) { return 'system'; }
    }

    function applyTheme(pref) {
        var effective = pref;
        if (pref === 'system') {
            effective = window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
        }
        document.documentElement.setAttribute('data-theme', effective);
        try {
            var bgColor = effective === 'light' ? '#e9e9e8' : '#161617';
            tg.setHeaderColor(bgColor);
            tg.setBackgroundColor(bgColor);
        } catch (e) {}
        updateThemeIcon(pref);
    }

    function updateThemeIcon(pref) {
        var btn = document.getElementById('theme-switcher');
        if (!btn) return;
        btn.innerHTML = THEME_ICONS[pref];
        btn.setAttribute('data-current', pref);
    }

    window.cycleTheme = function () {
        var current = getStoredTheme();
        var next = THEMES[(THEMES.indexOf(current) + 1) % THEMES.length];
        try { localStorage.setItem(THEME_KEY, next); } catch (e) {}
        applyTheme(next);
        haptic('selection');
    };

    window.matchMedia('(prefers-color-scheme: light)').addEventListener('change', function () {
        if (getStoredTheme() === 'system') applyTheme('system');
    });

    applyTheme(getStoredTheme());

    const initData = tg.initData;
    let statusData = null;
    let groupsData = null;
    let dnsData = null;
    let routingData = null;
    let usersData = null;
    let meData = null;
    let groupsLoaded = false;
    let dnsLoaded = false;
    let routingLoaded = false;
    let usersLoaded = false;
    let currentConfigText = "";
    let currentConfigName = "";
    let currentConfigId = null;
    let deleteCallback = null;
    let editingPeerId = null;
    let editingPeerName = null;
    let peerEditDisabled = false;
    let peerEditExcludePrivate = true;
    let peerEditExcludeServer = false;
    let editingSecretHex = null;
    let editingProxyName = null;
    let editingCIDR = null;
    let editingIPRuleName = null;
    let editingSNIRuleName = null;
    let editingPortRuleName = null;
    let editingProtocolRuleName = null;
    let knownBlocklists = null;
    let selectedBlocklists = {};
    let editingUpstreamName = null;
    let upstreamEditDefaultOn = false;
    let upstreamEditHealthOn = false;
    let editingGroupName = null;
    let groupEditOriginalMembers = {};
    let editingUserID = null;
    let userEditDisabled = false;
    let invitesData = null;
    let invitesLoaded = false;
    let peersOnlyMine = false;
    let secretsOnlyMine = false;

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
    function showToast(message, isError) {
        const t = document.getElementById("toast");
        document.getElementById("toast-message").textContent = message;
        document.getElementById("toast-icon-success").style.display = isError ? "none" : "";
        document.getElementById("toast-icon-error").style.display = isError ? "" : "none";
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
        if (page === "routing" && !routingLoaded) refreshRouting();
        if (page === "users" && !usersLoaded) refreshUsers();

        try {
            if (page !== "admin") sessionStorage.setItem("activeTab", page);
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
            var ver = d.daemon.version;
            if (ver) {
                var versionEl = document.getElementById("admin-version");
                var label = ver.startsWith("v") ? ver : "v" + ver;
                if (d.daemon.dirty) label += " (dirty)";
                versionEl.textContent = label;
            }
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

    function refreshRouting() {
        api("GET", "/api/routing").then((d) => {
            routingData = d;
            routingLoaded = true;
            renderRouting();
        });
    }

    function refreshUsers() {
        api("GET", "/api/users").then((d) => {
            usersData = d;
            usersLoaded = true;
            renderUsers();
        });
        if (isAdmin()) {
            api("GET", "/api/invites").then((d) => {
                invitesData = d;
                invitesLoaded = true;
                renderInvites();
            });
        }
    }

    // --- Render: Peers ---
    function renderPeers() {
        if (!statusData) return;
        const allPeers = statusData.peers || [];
        const myUID = meData && meData.user_id;
        const peers = (peersOnlyMine && myUID)
            ? allPeers.filter((p) => p.owner_id === myUID)
            : allPeers;
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
                const pid = p.id;
                return (
                    '<div class="list-item' + (p.disabled ? ' disabled' : '') + '">' +
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
                    (p.last_handshake_unix > 0
                        ? " • " + timeAgo(p.last_handshake_unix)
                        : "") +
                    (p.owner_name ? " • 👤 " + escapeHtml(p.owner_name) : "") +
                    "</div></div>" +
                    '<div class="item-action">' +
                    '<div class="toggle-switch ' +
                    (p.disabled ? "" : "active") +
                    '" onclick="togglePeer(' +
                    pid +
                    "," +
                    p.disabled +
                    ',event)"><div class="toggle-knob"></div></div>' +
                    '<button class="action-icon-btn" onclick="openPeerEditModal(' +
                    pid +
                    ')" title="Edit"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg></button>' +
                    '<button class="action-icon-btn" onclick="showPeerConf(' +
                    pid +
                    ')" title="Config"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M8 21h12a2 2 0 0 0 2-2v-2H10v2a2 2 0 1 1-4 0V5a2 2 0 0 0-2-2H3"/><path d="M19 17V5a2 2 0 0 0-2-2H4a2 2 0 0 0-2 2v2h12v14"/></svg></button>' +
                    '<button class="action-icon-btn" onclick="showPeerQR(' +
                    pid +
                    ')" title="QR"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg></button>' +
                    '<button class="delete-btn" onclick="promptDelete(' +
                    pid +
                    ',\'peer\')" title="Delete"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg></button>' +
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
                const healthClass = !u.enabled
                    ? ""
                    : u.state === "healthy"
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
                const disabledClass = !u.enabled ? " disabled" : "";
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
                    '<div class="list-item' + disabledClass + '">' +
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
                          '<button class="action-icon-btn" onclick="openUpstreamEditModal(\'' +
                          escapedName +
                          '\')" title="Edit"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg></button>' +
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
                        ? '<div class="item-action">' +
                          '<button class="action-icon-btn" onclick="openGroupEditModal(\'' +
                          escapedName +
                          '\')" title="Edit"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg></button>' +
                          '<button class="delete-btn" onclick="promptDelete(\'' +
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
                        ? '<button class="action-icon-btn" onclick="copyText(\'' +
                          p.link.replace(/'/g, "\\'") +
                          "',event)\" title=\"Copy\"><svg width=\"20\" height=\"20\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"><rect x=\"9\" y=\"9\" width=\"13\" height=\"13\" rx=\"2\" ry=\"2\"/><path d=\"M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1\"/></svg></button>"
                        : "") +
                    (isAdmin()
                        ? '<button class="action-icon-btn" onclick="openProxyEditModal(\'' +
                          escapedName +
                          '\')" title="Edit"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg></button>' +
                          '<button class="delete-btn" onclick="promptDelete(\'' +
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
                    var peerScope = (r.peers && r.peers.length > 0)
                        ? escapeHtml(r.peers.map(function(p) { return p.name; }).join(", "))
                        : "All peers";
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
                        ' • 👤 ' + peerScope +
                        "</div>" +
                        "</div>" +
                        (isAdmin()
                            ? '<div class="item-action">' +
                              '<button class="action-icon-btn" onclick="editDNSRule(\'' +
                              escapedName +
                              '\')" title="Edit"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg></button>' +
                              '<button class="delete-btn" onclick="promptDelete(\'' +
                              escapedName +
                              '\',\'dns-rule\')"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg></button></div>'
                            : "") +
                        "</div>"
                    );
                })
                .join("");
        }
    }

    // --- Render: Routing ---
    // --- Drag & Drop Reorder ---
    var dragState = { el: null, list: null, type: null };
    var dragHandleSvg = '<svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><circle cx="9" cy="6" r="2"/><circle cx="15" cy="6" r="2"/><circle cx="9" cy="12" r="2"/><circle cx="15" cy="12" r="2"/><circle cx="9" cy="18" r="2"/><circle cx="15" cy="18" r="2"/></svg>';

    function initDragList(listEl, type) {
        listEl.addEventListener('dragstart', function(e) {
            var item = e.target.closest('.list-item');
            if (!item) return;
            dragState.el = item;
            dragState.list = listEl;
            dragState.type = type;
            item.classList.add('dragging');
            e.dataTransfer.effectAllowed = 'move';
            e.dataTransfer.setData('text/plain', '');
        });
        listEl.addEventListener('dragend', function(e) {
            var item = e.target.closest('.list-item');
            if (item) item.classList.remove('dragging');
            listEl.querySelectorAll('.list-item').forEach(function(el) {
                el.classList.remove('drag-over');
            });
            if (dragState.el && dragState.list === listEl) {
                saveReorder(listEl, type);
            }
            dragState = { el: null, list: null, type: null };
        });
        listEl.addEventListener('dragover', function(e) {
            e.preventDefault();
            e.dataTransfer.dropEffect = 'move';
            var target = e.target.closest('.list-item');
            if (!target || target === dragState.el || target.parentNode !== listEl) return;
            listEl.querySelectorAll('.list-item').forEach(function(el) {
                el.classList.remove('drag-over');
            });
            var rect = target.getBoundingClientRect();
            var mid = rect.top + rect.height / 2;
            if (e.clientY < mid) {
                target.classList.add('drag-over');
                listEl.insertBefore(dragState.el, target);
            } else {
                listEl.insertBefore(dragState.el, target.nextSibling);
            }
        });
        listEl.addEventListener('drop', function(e) {
            e.preventDefault();
        });

        // Touch drag support
        var touchDrag = { el: null, clone: null, startY: 0, moved: false };
        listEl.addEventListener('touchstart', function(e) {
            var handle = e.target.closest('.drag-handle');
            if (!handle) return;
            var item = handle.closest('.list-item');
            if (!item) return;
            e.preventDefault();
            touchDrag.el = item;
            touchDrag.startY = e.touches[0].clientY;
            touchDrag.moved = false;
            item.classList.add('dragging');
            haptic('selection');
        }, { passive: false });
        listEl.addEventListener('touchmove', function(e) {
            if (!touchDrag.el) return;
            e.preventDefault();
            touchDrag.moved = true;
            var y = e.touches[0].clientY;
            var items = Array.from(listEl.querySelectorAll('.list-item'));
            items.forEach(function(el) { el.classList.remove('drag-over'); });
            for (var i = 0; i < items.length; i++) {
                if (items[i] === touchDrag.el) continue;
                var rect = items[i].getBoundingClientRect();
                var mid = rect.top + rect.height / 2;
                if (y < mid) {
                    items[i].classList.add('drag-over');
                    listEl.insertBefore(touchDrag.el, items[i]);
                    break;
                } else if (i === items.length - 1 || y < rect.bottom) {
                    listEl.insertBefore(touchDrag.el, items[i].nextSibling);
                    break;
                }
            }
        }, { passive: false });
        listEl.addEventListener('touchend', function(e) {
            if (!touchDrag.el) return;
            touchDrag.el.classList.remove('dragging');
            listEl.querySelectorAll('.list-item').forEach(function(el) {
                el.classList.remove('drag-over');
            });
            if (touchDrag.moved) {
                saveReorder(listEl, type);
            }
            touchDrag = { el: null, clone: null, startY: 0, moved: false };
        });
    }

    function saveReorder(listEl, type) {
        var items = Array.from(listEl.querySelectorAll('.list-item'));
        var keys = items.map(function(el) { return el.dataset.key; }).filter(Boolean);
        if (keys.length === 0) return;

        var endpoint, body;
        if (type === 'cidrs') {
            endpoint = '/api/routing/cidrs/order';
            body = { cidrs: keys };
        } else if (type === 'ip-rules') {
            endpoint = '/api/routing/ip-rules/order';
            body = { names: keys };
        } else {
            return;
        }

        api('PUT', endpoint, body).then(function(d) {
            if (d.error) {
                haptic('notification', 'error');
                showToast(d.error, true);
                refreshRouting();
                return;
            }
            haptic('notification', 'success');
            showToast('Order saved');
        });
    }

    function renderRouting() {
        if (!routingData) return;

        // Status
        const badge = document.getElementById("routing-status-badge");
        const text = document.getElementById("routing-status-text");
        if (routingData.enabled) {
            badge.textContent = "ON";
            badge.className = "status-badge active";
            text.textContent = "Routing rules active";
        } else {
            badge.textContent = "OFF";
            badge.className = "status-badge inactive";
            text.textContent = "Disabled";
        }

        // CIDRs
        const cidrEl = document.getElementById("routing-cidr-list");
        const cidrs = routingData.cidrs || [];
        if (cidrs.length === 0) {
            cidrEl.innerHTML = '<div class="empty-state">No CIDRs configured</div>';
        } else {
            cidrEl.innerHTML = cidrs.map(c => {
                const cidr = c.cidr;
                const mode = c.mode || 'allow';
                const escapedCIDR = cidr.replace(/'/g, "\\'");
                const isExclude = mode === 'disallow';
                const modeBadge = isExclude
                    ? '<span class="rule-type-badge block">Direct</span>'
                    : '<span class="rule-type-badge upstream">Allow</span>';
                return '<div class="list-item" draggable="' + (isAdmin() ? 'true' : 'false') + '" data-key="' + escapeHtml(cidr) + '">' +
                    (isAdmin() ? '<div class="drag-handle">' + dragHandleSvg + '</div>' : '') +
                    '<div class="item-icon routing-cidr"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg></div>' +
                    '<div class="item-content">' +
                    '<div class="item-title">' + escapeHtml(cidr) + '</div>' +
                    '<div class="item-subtitle">' + modeBadge + '</div>' +
                    '</div>' +
                    (isAdmin() ? '<div class="item-action">' +
                        '<button class="action-icon-btn" onclick="openCIDREditModal(\'' + escapedCIDR + '\')" title="Edit"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg></button>' +
                        '<button class="delete-btn" onclick="promptDelete(\'' + escapedCIDR + '\',\'routing-cidr\')"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg></button>' +
                    '</div>' : '') +
                    '</div>';
            }).join('');
            if (isAdmin()) initDragList(cidrEl, 'cidrs');
        }

        // IP Rules
        const ipEl = document.getElementById("routing-ip-rule-list");
        const ipRules = routingData.ip_rules || [];
        if (ipRules.length === 0) {
            ipEl.innerHTML = '<div class="empty-state">No IP rules</div>';
        } else {
            ipEl.innerHTML = ipRules.map(r => {
                const actionBadge = r.action === 'direct'
                    ? '<span class="rule-type-badge block">Direct</span>'
                    : '<span class="rule-type-badge upstream">Upstream</span>';
                const info = [];
                if ((r.cidrs || []).length > 0) info.push((r.cidrs || []).length + ' CIDR' + ((r.cidrs || []).length > 1 ? 's' : ''));
                if ((r.asns || []).length > 0) info.push((r.asns || []).length + ' ASN' + ((r.asns || []).length > 1 ? 's' : ''));
                if ((r.lists || []).length > 0) info.push((r.lists || []).length + ' list' + ((r.lists || []).length > 1 ? 's' : ''));
                if (r.upstream_group) info.push('→ ' + r.upstream_group);
                var peerScope = (r.peers && r.peers.length > 0)
                    ? escapeHtml(r.peers.map(function(p) { return p.name; }).join(", "))
                    : "All peers";
                const escapedName = r.name.replace(/'/g, "\\'");
                return '<div class="list-item" draggable="' + (isAdmin() ? 'true' : 'false') + '" data-key="' + escapeHtml(r.name) + '">' +
                    (isAdmin() ? '<div class="drag-handle">' + dragHandleSvg + '</div>' : '') +
                    '<div class="item-icon routing-ip-rule"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg></div>' +
                    '<div class="item-content">' +
                    '<div class="item-title">' + escapeHtml(r.name) + '</div>' +
                    '<div class="item-subtitle">' + actionBadge + ' • ' + info.join(' • ') + ' • 👤 ' + peerScope + '</div>' +
                    '</div>' +
                    (isAdmin() ? '<div class="item-action">' +
                        '<button class="action-icon-btn" onclick="openIPRuleEditModal(\'' + escapedName + '\')" title="Edit"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg></button>' +
                        '<button class="delete-btn" onclick="promptDelete(\'' + escapedName + '\',\'ip-rule\')"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg></button>' +
                    '</div>' : '') +
                    '</div>';
            }).join('');
            if (isAdmin()) initDragList(ipEl, 'ip-rules');
        }

        // SNI Rules
        const sniEl = document.getElementById("routing-sni-rule-list");
        const sniRules = routingData.sni_rules || [];
        if (sniRules.length === 0) {
            sniEl.innerHTML = '<div class="empty-state">No SNI rules</div>';
        } else {
            sniEl.innerHTML = sniRules.map(r => {
                const actionBadge = r.action === 'direct'
                    ? '<span class="rule-type-badge block">Direct</span>'
                    : '<span class="rule-type-badge upstream">Upstream</span>';
                const domainCount = (r.domains || []).length;
                const info = [];
                if (domainCount > 0) info.push(domainCount + ' domain' + (domainCount > 1 ? 's' : ''));
                if (r.upstream_group) info.push('→ ' + r.upstream_group);
                var sniPeerScope = (r.peers && r.peers.length > 0)
                    ? escapeHtml(r.peers.map(function(p) { return p.name; }).join(", "))
                    : "All peers";
                const escapedName = r.name.replace(/'/g, "\\'");
                return '<div class="list-item">' +
                    '<div class="item-icon routing-sni-rule"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg></div>' +
                    '<div class="item-content">' +
                    '<div class="item-title">' + escapeHtml(r.name) + '</div>' +
                    '<div class="item-subtitle">' + actionBadge + ' • ' + info.join(' • ') + ' • 👤 ' + sniPeerScope + '</div>' +
                    '</div>' +
                    (isAdmin() ? '<div class="item-action">' +
                        '<button class="action-icon-btn" onclick="openSNIRuleEditModal(\'' + escapedName + '\')" title="Edit"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg></button>' +
                        '<button class="delete-btn" onclick="promptDelete(\'' + escapedName + '\',\'sni-rule\')"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg></button>' +
                    '</div>' : '') +
                    '</div>';
            }).join('');
        }

        // Port Rules
        const portEl = document.getElementById("routing-port-rule-list");
        const portRules = routingData.port_rules || [];
        if (portRules.length === 0) {
            portEl.innerHTML = '<div class="empty-state">No port rules</div>';
        } else {
            portEl.innerHTML = portRules.map(r => {
                const actionBadge = r.action === 'block'
                    ? '<span class="rule-type-badge block">Block</span>'
                    : r.action === 'direct'
                    ? '<span class="rule-type-badge block">Direct</span>'
                    : '<span class="rule-type-badge upstream">Upstream</span>';
                const portCount = (r.ports || []).length;
                const info = [];
                if (portCount > 0) info.push(portCount + ' port' + (portCount > 1 ? 's' : ''));
                if (r.upstream_group) info.push('→ ' + r.upstream_group);
                var portPeerScope = (r.peers && r.peers.length > 0)
                    ? escapeHtml(r.peers.map(function(p) { return p.name; }).join(", "))
                    : "All peers";
                const escapedName = r.name.replace(/'/g, "\\'");
                return '<div class="list-item">' +
                    '<div class="item-icon routing-sni-rule"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg></div>' +
                    '<div class="item-content">' +
                    '<div class="item-title">' + escapeHtml(r.name) + '</div>' +
                    '<div class="item-subtitle">' + actionBadge + ' • ' + info.join(' • ') + ' • 👤 ' + portPeerScope + '</div>' +
                    '</div>' +
                    (isAdmin() ? '<div class="item-action">' +
                        '<button class="action-icon-btn" onclick="openPortRuleEditModal(\'' + escapedName + '\')" title="Edit"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg></button>' +
                        '<button class="delete-btn" onclick="promptDelete(\'' + escapedName + '\',\'port-rule\')"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg></button>' +
                    '</div>' : '') +
                    '</div>';
            }).join('');
        }

        // Protocol Rules
        const protoEl = document.getElementById("routing-protocol-rule-list");
        const protoRules = routingData.protocol_rules || [];
        if (protoRules.length === 0) {
            protoEl.innerHTML = '<div class="empty-state">No protocol rules</div>';
        } else {
            protoEl.innerHTML = protoRules.map(r => {
                const actionBadge = r.action === 'block'
                    ? '<span class="rule-type-badge block">Block</span>'
                    : r.action === 'direct'
                    ? '<span class="rule-type-badge block">Direct</span>'
                    : '<span class="rule-type-badge upstream">Upstream</span>';
                const protoCount = (r.protocols || []).length;
                const info = [];
                if (protoCount > 0) info.push(protoCount + ' protocol' + (protoCount > 1 ? 's' : ''));
                if (r.upstream_group) info.push('→ ' + r.upstream_group);
                var protoPeerScope = (r.peers && r.peers.length > 0)
                    ? escapeHtml(r.peers.map(function(p) { return p.name; }).join(", "))
                    : "All peers";
                const escapedName = r.name.replace(/'/g, "\\'");
                return '<div class="list-item">' +
                    '<div class="item-icon routing-sni-rule"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg></div>' +
                    '<div class="item-content">' +
                    '<div class="item-title">' + escapeHtml(r.name) + '</div>' +
                    '<div class="item-subtitle">' + actionBadge + ' • ' + info.join(' • ') + ' • 👤 ' + protoPeerScope + '</div>' +
                    '</div>' +
                    (isAdmin() ? '<div class="item-action">' +
                        '<button class="action-icon-btn" onclick="openProtocolRuleEditModal(\'' + escapedName + '\')" title="Edit"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg></button>' +
                        '<button class="delete-btn" onclick="promptDelete(\'' + escapedName + '\',\'protocol-rule\')"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg></button>' +
                    '</div>' : '') +
                    '</div>';
            }).join('');
        }
    }

    // --- Render: Users ---
    function renderUsers() {
        if (!usersData) return;
        const el = document.getElementById("user-list");

        document.getElementById("user-stat-total").textContent = usersData.length;
        document.getElementById("user-stat-admin").textContent = usersData.filter(u => u.is_admin).length;

        if (usersData.length === 0) {
            el.innerHTML = '<div class="empty-state">No users</div>';
            return;
        }

        el.innerHTML = usersData.map(u => {
            const displayName = u.custom_name || (u.first_name || '') + (u.last_name ? ' ' + u.last_name : '') || u.username || 'User ' + u.user_id;
            const iconClass = u.is_admin ? 'item-icon user' : 'item-icon user-guest';
            const roleBadge = u.is_admin
                ? '<span class="status-badge admin">Admin</span>'
                : '<span class="status-badge guest">Guest</span>';
            const initial = displayName.charAt(0).toUpperCase();
            const avatarContent = u.photo_url
                ? '<img src="' + escapeHtml(u.photo_url) + '" alt="' + initial + '">'
                : initial;
            const canEdit = !u.is_config_admin && isAdmin();
            const canDelete = !u.is_config_admin && isAdmin();
            const disabledClass = u.disabled ? ' disabled' : '';
            return '<div class="list-item' + disabledClass + '">' +
                '<div class="' + iconClass + '"><div class="user-avatar">' + avatarContent + '</div></div>' +
                '<div class="item-content">' +
                '<div class="item-title">' + escapeHtml(displayName) + '</div>' +
                '<div class="item-subtitle">' +
                (u.username ? '@' + escapeHtml(u.username) + ' • ' : '') +
                'ID: ' + u.user_id + ' • ' + roleBadge +
                (u.is_config_admin ? ' <span class="status-badge inactive">config</span>' : '') +
                (u.disabled ? ' <span class="status-badge inactive">disabled</span>' : '') +
                '</div></div>' +
                '<div class="item-action">' +
                (canEdit
                    ? '<button class="action-icon-btn" onclick="openUserEditModal(' + u.user_id + ')" title="Edit"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg></button>'
                    : '') +
                (canDelete
                    ? '<button class="delete-btn" onclick="promptDelete(' + u.user_id + ',\'user\')"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg></button>'
                    : '') +
                '</div></div>';
        }).join('');
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

        const allSecrets = mt.secrets || [];
        const myUID = meData && meData.user_id;
        const secrets = (secretsOnlyMine && myUID)
            ? allSecrets.filter((s) => s.owner_id === myUID)
            : allSecrets;
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
            secEl.innerHTML = '<div class="empty-state">No secrets configured</div>';
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
                        (s.owner_name ? ' • 👤 ' + escapeHtml(s.owner_name) : '') +
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
        document.body.style.overflow = "hidden";
    }

    function closeModal(id) {
        document.getElementById(id + "-backdrop").classList.remove("open");
        document.getElementById(id + "-sheet").classList.remove("open");
        document.body.style.overflow = "";
    }

    // --- Filter: Only Mine ---
    window.togglePeersOnlyMine = function () {
        peersOnlyMine = !peersOnlyMine;
        var cb = document.getElementById("peers-only-mine-cb");
        if (peersOnlyMine) cb.classList.add("checked");
        else cb.classList.remove("checked");
        haptic("selection");
        renderPeers();
    };
    window.toggleSecretsOnlyMine = function () {
        secretsOnlyMine = !secretsOnlyMine;
        var cb = document.getElementById("secrets-only-mine-cb");
        if (secretsOnlyMine) cb.classList.add("checked");
        else cb.classList.remove("checked");
        haptic("selection");
        renderMTProxy();
    };

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
                showToast(d.error, true);
                return;
            }
            haptic("notification", "success");
            showToast("Peer created");
            closePeerModal();
            refresh();
        });
    };

    window.openPeerEditModal = function (id) {
        if (!statusData) return;
        const peer = (statusData.peers || []).find((p) => p.id === id);
        if (!peer) return;
        editingPeerId = id;
        editingPeerName = peer.name || "";
        const name = editingPeerName;
        peerEditDisabled = peer.disabled;
        peerEditExcludePrivate = peer.exclude_private !== false;
        peerEditExcludeServer = peer.exclude_server === true;
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
        updatePeerEditExcludePrivateToggle();
        updatePeerEditExcludeServerToggle();
        openModal("peer-edit-modal");
    };
    window.closePeerEditModal = function () {
        closeModal("peer-edit-modal");
        editingPeerId = null;
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
    window.togglePeerEditExcludePrivate = function () {
        peerEditExcludePrivate = !peerEditExcludePrivate;
        updatePeerEditExcludePrivateToggle();
        haptic("selection");
    };
    function updatePeerEditExcludePrivateToggle() {
        const el = document.getElementById("peer-edit-exclude-private-toggle");
        const label = document.getElementById("peer-edit-exclude-private-label");
        if (peerEditExcludePrivate) {
            el.classList.add("active");
            label.textContent = "Enabled";
        } else {
            el.classList.remove("active");
            label.textContent = "Disabled";
        }
    }
    window.togglePeerEditExcludeServer = function () {
        peerEditExcludeServer = !peerEditExcludeServer;
        updatePeerEditExcludeServerToggle();
        haptic("selection");
    };
    function updatePeerEditExcludeServerToggle() {
        const el = document.getElementById("peer-edit-exclude-server-toggle");
        const label = document.getElementById("peer-edit-exclude-server-label");
        if (peerEditExcludeServer) {
            el.classList.add("active");
            label.textContent = "Enabled";
        } else {
            el.classList.remove("active");
            label.textContent = "Disabled";
        }
    }
    window.savePeerEdit = function () {
        if (editingPeerId == null) return;
        const newName = document
            .getElementById("inp-peer-edit-name")
            .value.trim();
        if (!newName) {
            haptic("notification", "error");
            showToast("Name cannot be empty");
            return;
        }
        const body = { disabled: peerEditDisabled, exclude_private: peerEditExcludePrivate, exclude_server: peerEditExcludeServer };
        if (newName !== editingPeerName) {
            body.name = newName;
        }
        const upstreamGroup = document.getElementById("inp-peer-edit-upstream-group").value;
        body.upstream_group = upstreamGroup;
        api(
            "PUT",
            "/api/peers/" + editingPeerId,
            body,
        ).then((d) => {
            if (d.error) {
                haptic("notification", "error");
                showToast(d.error, true);
                return;
            }
            haptic("notification", "success");
            showToast("Peer updated");
            closePeerEditModal();
            refresh();
        });
    };

    window.showPeerConf = function (id) {
        const peer = (statusData && statusData.peers || []).find((p) => p.id === id);
        const name = peer ? (peer.name || "peer") : "peer";
        api("GET", "/api/peers/" + id + "/conf").then(
            (d) => {
                if (d.error) {
                    showToast(d.error, true);
                    return;
                }
                currentConfigText = d.config;
                currentConfigName = name;
                currentConfigId = id;
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

    window.showPeerQR = function (id) {
        const peer = (statusData && statusData.peers || []).find((p) => p.id === id);
        const name = peer ? (peer.name || "peer") : "peer";
        document.getElementById("config-modal-title").textContent =
            name + " QR";
        document.getElementById("config-action-btns").style.display =
            "none";
        const container = document.getElementById("config-modal-content");
        var qrUrl = "/api/peers/" + id + "/qr?_auth=" + encodeURIComponent(initData);
        container.innerHTML =
            '<div class="qr-container"><img src="' + qrUrl + '" alt="QR Code" style="max-width:90%;max-height:75vh;image-rendering:pixelated;" onerror="this.parentElement.innerHTML=\'<div class=\\\'empty-state\\\'>QR generation failed</div>\'"></div>';
        openModal("config-modal");
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
        var fileName = (currentConfigName || "peer").toLowerCase().replace(/\s+/g, "_") + ".conf";
        if (tg && tg.downloadFile) {
            var downloadUrl = location.origin + "/api/peers/" + currentConfigId + "/conf?download=1&_auth=" + encodeURIComponent(initData);
            tg.downloadFile({ url: downloadUrl, file_name: fileName }, function (accepted) {
                if (accepted) {
                    haptic("notification", "success");
                    showToast("Download started");
                }
            });
        } else {
            var blob = new Blob([currentConfigText], { type: "text/plain" });
            var url = URL.createObjectURL(blob);
            var a = document.createElement("a");
            a.href = url;
            a.download = fileName;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            haptic("notification", "success");
            showToast("Download started");
        }
    };

    window.sendConfigToTelegram = function () {
        if (currentConfigId == null) return;
        api("POST", "/api/peers/" + currentConfigId + "/send").then((d) => {
            if (d.error) {
                haptic("notification", "error");
                showToast(d.error, true);
                return;
            }
            haptic("notification", "success");
            showToast("Config sent to Telegram");
        });
    };

    // --- Upstreams ---
    window.openUpstreamModal = function () {
        openModal("upstream-modal");
        document.getElementById("upstream-modal-title").textContent =
            "New Upstream";
        document.getElementById("inp-upstream-name").value = "";
        document.getElementById("inp-upstream-transport").value = "";
        document.getElementById("inp-upstream-groups").value = "";
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
        const groupsRaw = document.getElementById("inp-upstream-groups").value.trim();
        const groups = groupsRaw ? groupsRaw.split(",").map(s => s.trim()).filter(Boolean) : [];
        api("POST", "/api/upstreams", {
            name,
            type: "outline",
            transport,
            groups,
            default: upstreamDefaultOn,
            health_check: { enabled: upstreamHealthOn },
        }).then((d) => {
            if (d.error) {
                haptic("notification", "error");
                showToast(d.error, true);
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
                showToast(d.error, true);
                return;
            }
            haptic("notification", "success");
            showToast("Group created");
            closeGroupModal();
            refreshGroups();
        });
    };

    // --- Upstream Edit ---
    window.openUpstreamEditModal = function (name) {
        if (!statusData) return;
        const u = (statusData.upstreams || []).find(x => x.name === name);
        if (!u) return;
        editingUpstreamName = name;

        document.getElementById("upstream-edit-name").textContent = name;
        document.getElementById("upstream-edit-type").textContent = u.type.toUpperCase();
        document.getElementById("inp-upstream-edit-transport").value = "";
        // Filter out computed groups ("all", "default")
        const explicitGroups = (u.groups || []).filter(g => g !== "all" && g !== "default");
        document.getElementById("inp-upstream-edit-groups").value = explicitGroups.join(", ");

        upstreamEditDefaultOn = u.default;
        upstreamEditHealthOn = true;
        updateToggle("inp-upstream-edit-default", upstreamEditDefaultOn);
        updateToggle("inp-upstream-edit-health", upstreamEditHealthOn);

        var statsHtml =
            '<div class="peer-stat-card"><div class="peer-stat-value">' +
            (u.state || "unknown") +
            '</div><div class="peer-stat-label">State</div></div>' +
            '<div class="peer-stat-card"><div class="peer-stat-value">↓ ' +
            formatBytes(u.rx_bytes) +
            '</div><div class="peer-stat-label">Download</div></div>' +
            '<div class="peer-stat-card"><div class="peer-stat-value">↑ ' +
            formatBytes(u.tx_bytes) +
            '</div><div class="peer-stat-label">Upload</div></div>';
        if (u.active_connections > 0) {
            statsHtml += '<div class="peer-stat-card"><div class="peer-stat-value">' +
                u.active_connections +
                '</div><div class="peer-stat-label">Active</div></div>';
        }
        document.getElementById("upstream-edit-stats").innerHTML = statsHtml;

        openModal("upstream-edit-modal");
    };
    window.closeUpstreamEditModal = function () {
        closeModal("upstream-edit-modal");
        editingUpstreamName = null;
    };
    window.toggleUpstreamEditDefault = function () {
        upstreamEditDefaultOn = !upstreamEditDefaultOn;
        updateToggle("inp-upstream-edit-default", upstreamEditDefaultOn);
        haptic("selection");
    };
    window.toggleUpstreamEditHealth = function () {
        upstreamEditHealthOn = !upstreamEditHealthOn;
        updateToggle("inp-upstream-edit-health", upstreamEditHealthOn);
        haptic("selection");
    };
    window.saveUpstreamEdit = function () {
        if (!editingUpstreamName) return;

        var transport = document.getElementById("inp-upstream-edit-transport").value.trim();
        var groupsRaw = document.getElementById("inp-upstream-edit-groups").value.trim();
        var groups = groupsRaw ? groupsRaw.split(",").map(function(s) { return s.trim(); }).filter(Boolean) : [];

        var body = {
            default: upstreamEditDefaultOn,
            groups: groups,
            health_check: { enabled: upstreamEditHealthOn },
        };
        if (transport) {
            body.transport = transport;
        }

        api("PUT", "/api/upstreams/" + encodeURIComponent(editingUpstreamName), body).then(function(d) {
            if (d.error) {
                haptic("notification", "error");
                showToast(d.error, true);
                return;
            }
            haptic("notification", "success");
            showToast("Upstream updated");
            closeUpstreamEditModal();
            refresh();
            if (groupsLoaded) refreshGroups();
        });
    };

    // --- Group Edit ---
    window.openGroupEditModal = function (name) {
        editingGroupName = name;
        document.getElementById("group-edit-modal-title").textContent = "Edit Group: " + name;

        // Build member checkboxes from all upstreams
        var ups = (statusData && statusData.upstreams) || [];
        groupEditOriginalMembers = {};
        var html = "";
        ups.forEach(function (u) {
            var explicitGroups = (u.groups || []).filter(function(g) { return g !== "all" && g !== "default"; });
            var isMember = explicitGroups.indexOf(name) !== -1;
            groupEditOriginalMembers[u.name] = isMember;
            html += '<div class="toggle-row">' +
                '<div><div class="toggle-label">' + escapeHtml(u.name) + '</div>' +
                '<div class="toggle-sublabel">' + u.type.toUpperCase() + ' • ' + u.state + '</div></div>' +
                '<div class="toggle-switch' + (isMember ? ' active' : '') +
                '" id="group-member-' + u.name.replace(/[^a-zA-Z0-9]/g, '_') + '"' +
                ' onclick="toggleGroupMember(\'' + u.name.replace(/'/g, "\\'") + '\')"><div class="toggle-knob"></div></div>' +
                '</div>';
        });
        if (ups.length === 0) {
            html = '<div class="empty-state">No upstreams available</div>';
        }
        document.getElementById("group-edit-members").innerHTML = html;

        // Build consumers list
        var consumers = [];
        if (groupsData) {
            var grp = groupsData.find(function(g) { return g.name === name; });
            if (grp && grp.consumers) {
                consumers = grp.consumers.map(function(c) { return c.type + ": " + c.name; });
            }
        }
        document.getElementById("group-edit-consumers").textContent =
            consumers.length > 0 ? consumers.join(", ") : "None";

        openModal("group-edit-modal");
    };
    window.closeGroupEditModal = function () {
        closeModal("group-edit-modal");
        editingGroupName = null;
    };
    window.toggleGroupMember = function (upstreamName) {
        var elId = "group-member-" + upstreamName.replace(/[^a-zA-Z0-9]/g, '_');
        var el = document.getElementById(elId);
        if (el.classList.contains("active")) {
            el.classList.remove("active");
        } else {
            el.classList.add("active");
        }
        haptic("selection");
    };
    window.saveGroupEdit = function () {
        if (!editingGroupName) return;
        var ups = (statusData && statusData.upstreams) || [];
        var promises = [];

        ups.forEach(function (u) {
            var elId = "group-member-" + u.name.replace(/[^a-zA-Z0-9]/g, '_');
            var el = document.getElementById(elId);
            var nowMember = el && el.classList.contains("active");
            var wasMember = groupEditOriginalMembers[u.name] || false;

            if (nowMember !== wasMember) {
                // Get current explicit groups
                var currentGroups = (u.groups || []).filter(function(g) { return g !== "all" && g !== "default"; });
                var newGroups;
                if (nowMember) {
                    newGroups = currentGroups.concat([editingGroupName]);
                } else {
                    newGroups = currentGroups.filter(function(g) { return g !== editingGroupName; });
                }
                promises.push(
                    api("PUT", "/api/upstreams/" + encodeURIComponent(u.name), { groups: newGroups })
                );
            }
        });

        if (promises.length === 0) {
            closeGroupEditModal();
            return;
        }

        Promise.all(promises).then(function (results) {
            var errors = results.filter(function(d) { return d.error; });
            if (errors.length > 0) {
                haptic("notification", "error");
                showToast(errors[0].error, true);
                return;
            }
            haptic("notification", "success");
            showToast("Group updated");
            closeGroupEditModal();
            refresh();
            if (groupsLoaded) refreshGroups();
        });
    };

    window.togglePeer = function (id, currentlyDisabled, e) {
        if (e) e.stopPropagation();
        haptic("selection");
        api("PUT", "/api/peers/" + id, {
            disabled: !currentlyDisabled,
        }).then((d) => {
            if (d.error) {
                showToast(d.error, true);
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
                showToast(d.error, true);
                return;
            }
            refresh();
        });
    };

    // --- Proxies ---
    window.openProxyModal = function () {
        openModal("proxy-modal");
        document.getElementById("inp-proxy-name").value = "";
        document.getElementById("inp-proxy-port").value = "";
        document.getElementById("inp-proxy-username").value = "";
        document.getElementById("inp-proxy-password").value = "";
        document.getElementById("proxy-port-hint").textContent = "";
        document.getElementById("proxy-port-hint").className = "input-hint";
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
    window.checkPortAvailability = function () {
        const hint = document.getElementById("proxy-port-hint");
        const port = parseInt(document.getElementById("inp-proxy-port").value, 10);
        if (!port || port < 1 || port > 65535) {
            hint.textContent = "";
            hint.className = "input-hint";
            return;
        }
        const used = (statusData && statusData.used_ports) || [];
        const match = used.find((p) => p.port === port);
        if (match) {
            hint.textContent = "⚠ Port already used by " + match.owner;
            hint.className = "input-hint warn";
        } else {
            hint.textContent = "";
            hint.className = "input-hint";
        }
    };
    window.saveProxy = function () {
        const type = document.getElementById("inp-proxy-type").value;
        const port = document.getElementById("inp-proxy-port").value.trim();
        const name = document.getElementById("inp-proxy-name").value.trim();
        const username = document.getElementById("inp-proxy-username").value.trim();
        const password = document.getElementById("inp-proxy-password").value;
        if (!port || parseInt(port, 10) < 1 || parseInt(port, 10) > 65535) {
            haptic("notification", "error");
            return;
        }
        const listen = "0.0.0.0:" + port;
        api("POST", "/api/proxies", { name, type, listen, username, password }).then((d) => {
            if (d.error) {
                haptic("notification", "error");
                showToast(d.error, true);
                return;
            }
            haptic("notification", "success");
            showToast("Proxy added");
            closeProxyModal();
            refresh();
        });
    };

    // --- Proxy Edit ---
    window.openProxyEditModal = function (name) {
        if (!statusData) return;
        const proxy = (statusData.proxies || []).find((p) => p.name === name);
        if (!proxy) return;
        editingProxyName = name;

        document.getElementById("proxy-edit-name").textContent = name;
        document.getElementById("proxy-edit-type").textContent = proxy.type.toUpperCase();
        document.getElementById("proxy-edit-listen").textContent = proxy.listen;
        document.getElementById("inp-proxy-edit-username").value = proxy.username || "";
        document.getElementById("inp-proxy-edit-password").value = proxy.password || "";

        // Populate upstream group dropdown
        const sel = document.getElementById("inp-proxy-edit-upstream-group");
        const allGroups = [...new Set((statusData.upstreams || []).flatMap(u => u.groups || []))];
        sel.innerHTML = '<option value="">Default</option>' +
            allGroups.map(g => '<option value="' + escapeHtml(g) + '"' +
                (proxy.upstream_group === g ? ' selected' : '') + '>' + escapeHtml(g) + '</option>'
            ).join('');

        openModal("proxy-edit-modal");
    };
    window.closeProxyEditModal = function () {
        closeModal("proxy-edit-modal");
        editingProxyName = null;
    };
    window.saveProxyEdit = function () {
        if (!editingProxyName) return;
        const upstreamGroup = document.getElementById("inp-proxy-edit-upstream-group").value;
        const username = document.getElementById("inp-proxy-edit-username").value.trim();
        const password = document.getElementById("inp-proxy-edit-password").value;

        const body = { upstream_group: upstreamGroup };
        if (username || password) {
            body.username = username;
            body.password = password;
        }

        api("PUT", "/api/proxies/" + encodeURIComponent(editingProxyName), body).then((d) => {
            if (d.error) {
                haptic("notification", "error");
                showToast(d.error, true);
                return;
            }
            haptic("notification", "success");
            showToast("Proxy updated");
            closeProxyEditModal();
            refresh();
        });
    };

    // --- DNS Rules ---
    function renderBlocklistPicker() {
        var el = document.getElementById("dns-rule-blocklist-picker");
        if (!knownBlocklists || knownBlocklists.length === 0) {
            el.innerHTML = '<div class="empty-state" style="font-size:13px">No known blocklists</div>';
            return;
        }
        var sources = [];
        var bySource = {};
        knownBlocklists.forEach(function (bl) {
            if (!bySource[bl.source]) {
                bySource[bl.source] = [];
                sources.push(bl.source);
            }
            bySource[bl.source].push(bl);
        });
        var html = "";
        sources.forEach(function (src) {
            var label = src === "oisd" ? "OISD" : src === "hagezi" ? "Hagezi" : src;
            html += '<div class="blocklist-source-header">' + escapeHtml(label) + "</div>";
            bySource[src].forEach(function (bl) {
                var sel = selectedBlocklists[bl.name] ? " selected" : "";
                html +=
                    '<div class="blocklist-item' + sel + '" data-bl-name="' + escapeHtml(bl.name) + '" onclick="toggleBlocklistItem(this)">' +
                    '<div class="blocklist-item-cb"></div>' +
                    '<div class="blocklist-item-text">' +
                    '<div class="blocklist-item-name">' + escapeHtml(bl.name) + "</div>" +
                    '<div class="blocklist-item-desc">' + escapeHtml(bl.description) + "</div>" +
                    "</div></div>";
            });
        });
        el.innerHTML = html;
    }

    window.toggleBlocklistItem = function (el) {
        var name = el.getAttribute("data-bl-name");
        if (selectedBlocklists[name]) {
            delete selectedBlocklists[name];
            el.classList.remove("selected");
        } else {
            selectedBlocklists[name] = true;
            el.classList.add("selected");
        }
        haptic("selection");
    };

    var selectedDNSRulePeers = {};

    function renderDNSRulePeerPicker() {
        var el = document.getElementById("dns-rule-peer-picker");
        var peers = (statusData && statusData.peers) || [];
        if (peers.length === 0) {
            el.innerHTML = '<div class="empty-state" style="font-size:13px">No peers available</div>';
            return;
        }
        el.innerHTML = peers.map(function (p) {
            var name = p.name || p.public_key.slice(0, 8) + "...";
            var sel = selectedDNSRulePeers[name] ? " selected" : "";
            return '<div class="blocklist-item' + sel + '" data-peer-name="' + escapeHtml(name) + '" onclick="toggleDNSRulePeer(this)">' +
                '<div class="blocklist-item-cb"></div>' +
                '<div class="blocklist-item-text">' +
                '<div class="blocklist-item-name">' + escapeHtml(name) + '</div>' +
                '</div></div>';
        }).join("");
    }

    window.toggleDNSRulePeer = function (el) {
        var name = el.getAttribute("data-peer-name");
        if (selectedDNSRulePeers[name]) {
            delete selectedDNSRulePeers[name];
            el.classList.remove("selected");
        } else {
            selectedDNSRulePeers[name] = true;
            el.classList.add("selected");
        }
        haptic("selection");
    };

    // --- Routing: shared peer picker (reused by IP/SNI/Port/Protocol rule modals) ---
    var selectedRoutingPeers = {};

    function renderRoutingPeerPicker(containerId) {
        var el = document.getElementById(containerId);
        var peers = (statusData && statusData.peers) || [];
        if (peers.length === 0) {
            el.innerHTML = '<div class="empty-state" style="font-size:13px">No peers available</div>';
            return;
        }
        el.innerHTML = peers.map(function (p) {
            var name = p.name || p.public_key.slice(0, 8) + "...";
            var sel = selectedRoutingPeers[name] ? " selected" : "";
            return '<div class="blocklist-item' + sel + '" data-peer-name="' + escapeHtml(name) + '" onclick="toggleRoutingPeer(this)">' +
                '<div class="blocklist-item-cb"></div>' +
                '<div class="blocklist-item-text">' +
                '<div class="blocklist-item-name">' + escapeHtml(name) + '</div>' +
                '</div></div>';
        }).join("");
    }

    window.toggleRoutingPeer = function (el) {
        var name = el.getAttribute("data-peer-name");
        if (selectedRoutingPeers[name]) {
            delete selectedRoutingPeers[name];
            el.classList.remove("selected");
        } else {
            selectedRoutingPeers[name] = true;
            el.classList.add("selected");
        }
        haptic("selection");
    };

    let editingDNSRule = null;

    window.openDNSRuleModal = function (name, action, upstream, domains, lists, peers) {
        openModal("dns-rule-modal");
        editingDNSRule = name || null;
        document.getElementById("dns-rule-modal-title").textContent = name
            ? "Edit DNS Rule"
            : "New DNS Rule";
        var nameInput = document.getElementById("inp-dns-rule-name");
        nameInput.value = name || "";
        nameInput.disabled = !!name;
        document.getElementById("inp-dns-rule-action").value = action || "block";
        document.getElementById("inp-dns-rule-upstream").value = upstream || "";
        document.getElementById("inp-dns-rule-domains").value = (domains || []).join(", ");
        // Custom list URL: pick the first list that is NOT a known blocklist
        var knownUrls = {};
        if (knownBlocklists) {
            knownBlocklists.forEach(function (bl) { knownUrls[bl.url] = bl.name; });
        }
        var customList = null;
        selectedBlocklists = {};
        (lists || []).forEach(function (l) {
            var blName = knownUrls[l.url];
            if (blName) {
                selectedBlocklists[blName] = true;
            } else if (!customList) {
                customList = l;
            }
        });
        document.getElementById("inp-dns-rule-list-url").value = customList ? customList.url : "";
        document.getElementById("inp-dns-rule-list-format").value = customList ? customList.format || "auto" : "auto";
        selectedDNSRulePeers = {};
        (peers || []).forEach(function (p) { selectedDNSRulePeers[p] = true; });
        renderDNSRulePeerPicker();
        if (!knownBlocklists) {
            api("GET", "/api/dns/blocklists").then(function (d) {
                if (Array.isArray(d)) {
                    knownBlocklists = d;
                } else {
                    knownBlocklists = [];
                }
                // Re-classify lists now that we know the blocklists
                var knownUrls2 = {};
                knownBlocklists.forEach(function (bl) { knownUrls2[bl.url] = bl.name; });
                selectedBlocklists = {};
                customList = null;
                (lists || []).forEach(function (l) {
                    var blName = knownUrls2[l.url];
                    if (blName) {
                        selectedBlocklists[blName] = true;
                    } else if (!customList) {
                        customList = l;
                    }
                });
                document.getElementById("inp-dns-rule-list-url").value = customList ? customList.url : "";
                document.getElementById("inp-dns-rule-list-format").value = customList ? customList.format || "auto" : "auto";
                renderBlocklistPicker();
            });
        } else {
            renderBlocklistPicker();
        }
        toggleDNSRuleAction();
    };

    window.editDNSRule = function (name) {
        if (!dnsData) return;
        var rule = (dnsData.rules || []).find(function (r) { return r.name === name; });
        if (!rule) return;
        openDNSRuleModal(name, rule.action, rule.upstream, rule.domains, rule.lists, rule.peers);
    };
    window.closeDNSRuleModal = function () {
        closeModal("dns-rule-modal");
        editingDNSRule = null;
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
        const lists = [];
        if (knownBlocklists) {
            knownBlocklists.forEach(function (bl) {
                if (selectedBlocklists[bl.name]) {
                    lists.push({ url: bl.url, format: "adblock" });
                }
            });
        }
        if (listUrl) {
            lists.push({ url: listUrl, format: listFormat });
        }

        if (domains.length === 0 && lists.length === 0) {
            haptic("notification", "error");
            showToast("Add domains or a list");
            return;
        }

        var peers = Object.keys(selectedDNSRulePeers);

        var body = {
            action,
            upstream: action === "upstream" ? upstream : "",
            domains,
            lists,
            peers,
        };

        if (editingDNSRule) {
            api("PUT", "/api/dns/rules/" + encodeURIComponent(editingDNSRule), body).then((d) => {
                if (d.error) {
                    haptic("notification", "error");
                    showToast(d.error, true);
                    return;
                }
                haptic("notification", "success");
                showToast('Rule "' + name + '" updated');
                closeDNSRuleModal();
                refreshDNS();
            });
        } else {
            body.name = name;
            api("POST", "/api/dns", body).then((d) => {
                if (d.error) {
                    haptic("notification", "error");
                    showToast(d.error, true);
                    return;
                }
                haptic("notification", "success");
                showToast('Rule "' + name + '" added');
                closeDNSRuleModal();
                refreshDNS();
            });
        }
    };

    window.toggleDNSEnabled = function () {
        if (!isAdmin()) return;
        var newState = !(dnsData && dnsData.enabled);
        api("PUT", "/api/dns", { enabled: newState }).then(function () {
            refreshDNS();
            haptic("impact");
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
                    showToast(d.error, true);
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
                        showToast(d.error, true);
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
        document.getElementById("inp-user-custom-name").value = "";
    };
    window.closeUserModal = function () {
        closeModal("user-modal");
    };
    window.saveUser = function () {
        const user = document.getElementById("inp-user-input").value.trim();
        const role = document.getElementById("inp-user-role").value;
        const custom_name = document.getElementById("inp-user-custom-name").value.trim();
        if (!user) {
            haptic("notification", "error");
            return;
        }
        api("POST", "/api/users", { user, role, custom_name }).then((d) => {
            if (d.error) {
                haptic("notification", "error");
                showToast(d.error, true);
                return;
            }
            haptic("notification", "success");
            showToast("User added");
            closeUserModal();
            refreshUsers();
        });
    };

    window.openUserEditModal = function (userId) {
        if (!usersData) return;
        const u = usersData.find(x => x.user_id === userId);
        if (!u) return;
        editingUserID = userId;
        userEditDisabled = u.disabled || false;

        const displayName = (u.first_name || '') + (u.last_name ? ' ' + u.last_name : '') || u.username || 'User ' + u.user_id;
        document.getElementById("user-edit-info").textContent = (u.username ? '@' + u.username + ' • ' : '') + 'ID: ' + u.user_id;
        document.getElementById("inp-user-edit-custom-name").value = u.custom_name || '';
        document.getElementById("inp-user-edit-role").value = u.is_admin ? 'admin' : 'guest';
        document.getElementById("inp-user-edit-max-peers").value = u.max_peers != null ? u.max_peers : '';
        document.getElementById("inp-user-edit-max-secrets").value = u.max_secrets != null ? u.max_secrets : '';

        updateUserEditToggle();
        openModal("user-edit-modal");
    };
    window.closeUserEditModal = function () {
        closeModal("user-edit-modal");
        editingUserID = null;
    };
    window.toggleUserEditDisabled = function () {
        userEditDisabled = !userEditDisabled;
        updateUserEditToggle();
        haptic("selection");
    };
    function updateUserEditToggle() {
        const el = document.getElementById("user-edit-enabled-toggle");
        const label = document.getElementById("user-edit-status-label");
        if (userEditDisabled) {
            el.classList.remove("active");
            label.textContent = "Disabled";
        } else {
            el.classList.add("active");
            label.textContent = "Enabled";
        }
    }
    window.saveUserEdit = function () {
        if (!editingUserID) return;
        const custom_name = document.getElementById("inp-user-edit-custom-name").value.trim();
        const role = document.getElementById("inp-user-edit-role").value;
        const maxPeersVal = document.getElementById("inp-user-edit-max-peers").value;
        const maxSecretsVal = document.getElementById("inp-user-edit-max-secrets").value;
        const body = { custom_name, role, disabled: userEditDisabled };
        if (maxPeersVal !== '') body.max_peers = parseInt(maxPeersVal, 10);
        if (maxSecretsVal !== '') body.max_secrets = parseInt(maxSecretsVal, 10);
        api("PUT", "/api/users/" + editingUserID, body).then(d => {
            if (d.error) {
                haptic("notification", "error");
                showToast(d.error, true);
                return;
            }
            haptic("notification", "success");
            showToast("User updated");
            closeUserEditModal();
            refreshUsers();
        });
    };

    function renderInvites() {
        const el = document.getElementById("invite-list");
        if (!el) return;
        if (!invitesData || invitesData.length === 0) {
            el.innerHTML = '<div class="empty-state">No pending invites</div>';
            return;
        }
        el.innerHTML = invitesData.map(inv => {
            const roleBadge = inv.role === 'admin'
                ? '<span class="status-badge admin">Admin</span>'
                : '<span class="status-badge guest">Guest</span>';
            const inviteUrl = inv.link || (location.origin + '/?invite=' + inv.token);
            const escapedToken = inv.token.replace(/'/g, "\\'");
            const escapedUrl = inviteUrl.replace(/'/g, "\\'");
            return '<div class="list-item">' +
                '<div class="item-icon users"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg></div>' +
                '<div class="item-content">' +
                '<div class="item-title">' + inv.token.slice(0, 12) + '…</div>' +
                '<div class="item-subtitle">' + roleBadge + ' • ' + timeAgo(inv.created_at) + '</div>' +
                '</div>' +
                '<div class="item-action">' +
                '<button class="action-icon-btn" onclick="copyText(\'' + escapedUrl + '\',event)" title="Copy link"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg></button>' +
                '<button class="delete-btn" onclick="promptDelete(\'' + escapedToken + '\',\'invite\')" title="Delete"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg></button>' +
                '</div></div>';
        }).join('');
    }

    window.openInviteModal = function () {
        openModal("invite-modal");
        document.getElementById("inp-invite-role").value = "guest";
    };
    window.closeInviteModal = function () {
        closeModal("invite-modal");
    };
    window.saveInvite = function () {
        const role = document.getElementById("inp-invite-role").value;
        api("POST", "/api/invites", { role }).then(d => {
            if (d.error) {
                haptic("notification", "error");
                showToast(d.error, true);
                return;
            }
            haptic("notification", "success");
            const inviteUrl = d.link || (location.origin + '/?invite=' + d.token);
            navigator.clipboard.writeText(inviteUrl).then(() => {
                showToast("Invite created & copied!");
            }).catch(() => {
                showToast("Invite created");
            });
            closeInviteModal();
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
                showToast(d.error, true);
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
            "routing-cidr": "Are you sure you want to remove this CIDR?",
            "ip-rule": "Are you sure you want to remove this IP rule?",
            "sni-rule": "Are you sure you want to remove this SNI rule?",
            "port-rule": "Are you sure you want to remove this port rule?",
            "protocol-rule": "Are you sure you want to remove this protocol rule?",
            user: "Are you sure you want to remove this user?",
            secret: "Are you sure you want to remove this secret?",
            invite: "Are you sure you want to delete this invite link?",
        };
        document.getElementById("alert-message").textContent =
            (messages[type] || "Are you sure?") +
            " This action cannot be undone.";
        document.getElementById("alert-overlay").classList.add("open");

        deleteCallback = function () {
            const endpoints = {
                peer: {
                    method: "DELETE",
                    path: "/api/peers/" + id,
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
                "routing-cidr": {
                    method: "DELETE",
                    path: "/api/routing/cidrs/" + encodeURIComponent(id),
                },
                "ip-rule": {
                    method: "DELETE",
                    path: "/api/routing/ip-rules/" + encodeURIComponent(id),
                },
                "sni-rule": {
                    method: "DELETE",
                    path: "/api/routing/sni-rules/" + encodeURIComponent(id),
                },
                "port-rule": {
                    method: "DELETE",
                    path: "/api/routing/port-rules/" + encodeURIComponent(id),
                },
                "protocol-rule": {
                    method: "DELETE",
                    path: "/api/routing/protocol-rules/" + encodeURIComponent(id),
                },
                user: { method: "DELETE", path: "/api/users/" + id },
                invite: { method: "DELETE", path: "/api/invites/" + encodeURIComponent(id) },
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
                    showToast(d.error, true);
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
                if (type === "routing-cidr" || type === "ip-rule" || type === "sni-rule" || type === "port-rule" || type === "protocol-rule") refreshRouting();
                if (type === "user") refreshUsers();
                if (type === "invite") refreshUsers();
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

    // --- Routing: Toggle Enabled ---
    window.toggleRoutingEnabled = function () {
        if (!isAdmin()) return;
        var newState = !(routingData && routingData.enabled);
        api("PUT", "/api/routing", { enabled: newState }).then(function () {
            refreshRouting();
            haptic("impact");
        });
    };

    // --- Routing: CIDR Create Modal ---
    window.openRoutingCIDRModal = function () {
        editingCIDR = null;
        document.getElementById("cidr-edit-modal-title").textContent = "Add CIDR";
        document.getElementById("inp-cidr-edit-mode").value = "allow";
        document.getElementById("inp-cidr-edit-range").value = "";
        openModal("cidr-edit-modal");
    };
    window.closeRoutingCIDRModal = function () {
        closeModal("cidr-edit-modal");
        editingCIDR = null;
    };
    window.saveRoutingCIDR = function () { saveCIDREdit(); };

    // --- Routing: CIDR Edit Modal ---
    window.openCIDREditModal = function (cidr) {
        editingCIDR = cidr;
        document.getElementById("cidr-edit-modal-title").textContent = "Edit CIDR";
        // Look up mode from routingData
        var entry = (routingData.cidrs || []).find(function(c) { return c.cidr === cidr; });
        var mode = entry ? entry.mode : "allow";
        document.getElementById("inp-cidr-edit-mode").value = mode;
        document.getElementById("inp-cidr-edit-range").value = cidr;
        openModal("cidr-edit-modal");
    };
    window.closeCIDREditModal = function () {
        closeModal("cidr-edit-modal");
        editingCIDR = null;
    };
    window.saveCIDREdit = function () {
        const mode = document.getElementById("inp-cidr-edit-mode").value;
        const range = document.getElementById("inp-cidr-edit-range").value.trim();
        if (!range) {
            haptic("notification", "error");
            showToast("IP range is required");
            return;
        }

        if (editingCIDR) {
            // Update existing
            api("PUT", "/api/routing/cidrs/" + encodeURIComponent(editingCIDR), { cidr: range, mode: mode }).then(d => {
                if (d.error) {
                    haptic("notification", "error");
                    showToast(d.error, true);
                    return;
                }
                haptic("notification", "success");
                showToast("CIDR updated");
                closeCIDREditModal();
                refreshRouting();
            });
        } else {
            // Create new
            api("POST", "/api/routing/cidrs", { cidr: range, mode: mode }).then(d => {
                if (d.error) {
                    haptic("notification", "error");
                    showToast(d.error, true);
                    return;
                }
                haptic("notification", "success");
                showToast("CIDR added");
                closeCIDREditModal();
                refreshRouting();
            });
        }
    };

    // --- Routing: IP Rule Modal (create + edit) ---

    // Parse a CIDR string into {type, db, value}.
    function parseIPRuleEntry(cidr) {
        if (cidr.startsWith("geoip:")) {
            const rest = cidr.substring(6);
            const colonIdx = rest.indexOf(":");
            if (colonIdx !== -1) {
                return { type: "geoip", db: rest.substring(0, colonIdx), value: rest.substring(colonIdx + 1) };
            }
            return { type: "geoip", db: "", value: rest };
        }
        return { type: "cidr", db: "", value: cidr };
    }

    // Serialize entry rows back to {cidrs, asns}.
    function collectIPRuleEntries() {
        const cidrs = [];
        const asns = [];
        const container = document.getElementById("ip-rule-entries");
        const rows = container.querySelectorAll(".entry-row");
        rows.forEach(function (row) {
            const type = row.querySelector(".entry-type").value;
            const value = row.querySelector(".entry-value").value.trim();
            if (!value) return;
            if (type === "cidr") {
                cidrs.push(value);
            } else if (type === "asn") {
                const n = parseInt(value, 10);
                if (!isNaN(n)) asns.push(n);
            } else if (type === "geoip") {
                const dbSel = row.querySelector(".entry-db");
                const db = dbSel ? dbSel.value : "";
                if (db) {
                    cidrs.push("geoip:" + db + ":" + value);
                } else {
                    cidrs.push("geoip:" + value);
                }
            }
        });
        return { cidrs, asns };
    }

    function getGeoIPDBs() {
        return (routingData && routingData.geoip_dbs) || [];
    }

    function getGeoIPDBNames() {
        return getGeoIPDBs().map(function (db) { return db.name; });
    }

    function getGeoIPCountries(dbName) {
        const dbs = getGeoIPDBs();
        if (!dbName) {
            return dbs.length > 0 ? (dbs[0].countries || []) : [];
        }
        const db = dbs.find(function (d) { return d.name === dbName; });
        return db ? (db.countries || []) : [];
    }

    let entryIdCounter = 0;

    function updateEntryDatalist(inp, countries) {
        var listId = inp.getAttribute("list");
        if (listId) {
            var old = document.getElementById(listId);
            if (old) old.remove();
        }
        if (!countries || countries.length === 0) {
            inp.removeAttribute("list");
            return;
        }
        listId = "entry-dl-" + (++entryIdCounter);
        var dl = document.createElement("datalist");
        dl.id = listId;
        countries.forEach(function (code) {
            var o = document.createElement("option");
            o.value = code;
            dl.appendChild(o);
        });
        inp.parentNode.appendChild(dl);
        inp.setAttribute("list", listId);
    }

    // Add an entry row to the IP rule modal.
    window.addIPRuleEntry = function (type, db, value) {
        type = type || "cidr";
        db = db || "";
        value = value || "";

        const container = document.getElementById("ip-rule-entries");
        const row = document.createElement("div");
        row.className = "entry-row";

        // Type select
        const typeSel = document.createElement("select");
        typeSel.className = "entry-type";
        [["cidr", "CIDR"], ["geoip", "GeoIP"], ["asn", "ASN"]].forEach(function (opt) {
            const o = document.createElement("option");
            o.value = opt[0];
            o.textContent = opt[1];
            if (opt[0] === type) o.selected = true;
            typeSel.appendChild(o);
        });
        row.appendChild(typeSel);

        // DB select (geoip only)
        const dbSel = document.createElement("select");
        dbSel.className = "entry-db";
        const defaultOpt = document.createElement("option");
        defaultOpt.value = "";
        defaultOpt.textContent = "(default)";
        dbSel.appendChild(defaultOpt);
        getGeoIPDBNames().forEach(function (name) {
            const o = document.createElement("option");
            o.value = name;
            o.textContent = name;
            if (name === db) o.selected = true;
            dbSel.appendChild(o);
        });
        dbSel.style.display = type === "geoip" ? "" : "none";
        row.appendChild(dbSel);

        // Value input
        const inp = document.createElement("input");
        inp.type = "text";
        inp.className = "entry-value";
        inp.value = value;
        inp.autocomplete = "off";
        if (type === "cidr") inp.placeholder = "10.0.0.0/8";
        else if (type === "geoip") inp.placeholder = "RU";
        else if (type === "asn") inp.placeholder = "13335";
        row.appendChild(inp);

        // Attach datalist for geoip
        if (type === "geoip") {
            updateEntryDatalist(inp, getGeoIPCountries(db));
        }

        // Delete button
        const delBtn = document.createElement("button");
        delBtn.type = "button";
        delBtn.className = "entry-delete-btn";
        delBtn.innerHTML = "×";
        delBtn.onclick = function () { row.remove(); };
        row.appendChild(delBtn);

        // DB change handler — update datalist
        dbSel.onchange = function () {
            updateEntryDatalist(inp, getGeoIPCountries(dbSel.value));
        };

        // Type change handler
        typeSel.onchange = function () {
            const t = typeSel.value;
            dbSel.style.display = t === "geoip" ? "" : "none";
            if (t === "cidr") inp.placeholder = "10.0.0.0/8";
            else if (t === "geoip") inp.placeholder = "RU";
            else if (t === "asn") inp.placeholder = "13335";
            if (t === "geoip") {
                updateEntryDatalist(inp, getGeoIPCountries(dbSel.value));
            } else {
                updateEntryDatalist(inp, null);
            }
        };

        container.appendChild(row);
    };

    function clearIPRuleEntries() {
        document.getElementById("ip-rule-entries").innerHTML = "";
    }

    window.openIPRuleModal = function () {
        editingIPRuleName = null;
        document.getElementById("ip-rule-modal-title").textContent = "Add IP Rule";
        document.getElementById("inp-ip-rule-name").value = "";
        document.getElementById("inp-ip-rule-name").disabled = false;
        document.getElementById("inp-ip-rule-action").value = "direct";
        document.getElementById("inp-ip-rule-upstream-group").value = "";
        document.getElementById("inp-ip-rule-list-url").value = "";
        clearIPRuleEntries();
        addIPRuleEntry();
        selectedRoutingPeers = {};
        renderRoutingPeerPicker("ip-rule-peer-picker");
        toggleIPRuleAction();
        openModal("ip-rule-modal");
    };
    window.openIPRuleEditModal = function (name) {
        if (!routingData) return;
        const rule = (routingData.ip_rules || []).find(r => r.name === name);
        if (!rule) return;
        editingIPRuleName = name;
        document.getElementById("ip-rule-modal-title").textContent = "Edit IP Rule";
        document.getElementById("inp-ip-rule-name").value = name;
        document.getElementById("inp-ip-rule-name").disabled = true;
        document.getElementById("inp-ip-rule-action").value = rule.action;
        document.getElementById("inp-ip-rule-upstream-group").value = rule.upstream_group || "";
        document.getElementById("inp-ip-rule-list-url").value =
            (rule.lists || []).length > 0 ? rule.lists[0].url : "";
        clearIPRuleEntries();
        (rule.cidrs || []).forEach(function (cidr) {
            const parsed = parseIPRuleEntry(cidr);
            addIPRuleEntry(parsed.type, parsed.db, parsed.value);
        });
        (rule.asns || []).forEach(function (asn) {
            addIPRuleEntry("asn", "", String(asn));
        });
        if (document.getElementById("ip-rule-entries").children.length === 0) {
            addIPRuleEntry();
        }
        selectedRoutingPeers = {};
        (rule.peers || []).forEach(function (p) { selectedRoutingPeers[p] = true; });
        renderRoutingPeerPicker("ip-rule-peer-picker");
        toggleIPRuleAction();
        openModal("ip-rule-modal");
    };
    window.closeIPRuleModal = function () {
        closeModal("ip-rule-modal");
        editingIPRuleName = null;
    };
    window.toggleIPRuleAction = function () {
        const action = document.getElementById("inp-ip-rule-action").value;
        document.getElementById("ip-rule-upstream-group").style.display =
            action === "upstream" ? "" : "none";
    };
    window.saveIPRule = function () {
        const name = document.getElementById("inp-ip-rule-name").value.trim();
        const action = document.getElementById("inp-ip-rule-action").value;
        const upstreamGroup = document.getElementById("inp-ip-rule-upstream-group").value.trim();
        const listUrl = document.getElementById("inp-ip-rule-list-url").value.trim();

        if (!name) {
            haptic("notification", "error");
            return;
        }
        if (action === "upstream" && !upstreamGroup) {
            haptic("notification", "error");
            showToast("Upstream group required");
            return;
        }

        const entries = collectIPRuleEntries();
        const lists = listUrl ? [{ url: listUrl }] : [];

        if (entries.cidrs.length === 0 && entries.asns.length === 0 && lists.length === 0) {
            haptic("notification", "error");
            showToast("Add CIDRs, ASNs, or a list URL");
            return;
        }

        const body = {
            name,
            action,
            upstream_group: action === "upstream" ? upstreamGroup : "",
            cidrs: entries.cidrs,
            asns: entries.asns,
            lists,
            peers: Object.keys(selectedRoutingPeers),
        };

        if (editingIPRuleName) {
            api("PUT", "/api/routing/ip-rules/" + encodeURIComponent(editingIPRuleName), body).then(d => {
                if (d.error) {
                    haptic("notification", "error");
                    showToast(d.error, true);
                    return;
                }
                haptic("notification", "success");
                showToast('IP rule "' + name + '" updated');
                closeIPRuleModal();
                refreshRouting();
            });
        } else {
            api("POST", "/api/routing/ip-rules", body).then(d => {
                if (d.error) {
                    haptic("notification", "error");
                    showToast(d.error, true);
                    return;
                }
                haptic("notification", "success");
                showToast('IP rule "' + name + '" added');
                closeIPRuleModal();
                refreshRouting();
            });
        }
    };

    // --- Routing: SNI Rule Modal (create + edit) ---
    function populateSNIRuleGroupSelect(selected) {
        const sel = document.getElementById('inp-sni-rule-upstream-group');
        const allGroups = [...new Set((statusData && statusData.upstreams || []).flatMap(u => u.groups || []))];
        sel.innerHTML = '<option value="">— Select group —</option>' +
            allGroups.map(g => '<option value="' + escapeHtml(g) + '"' +
                (selected === g ? ' selected' : '') + '>' + escapeHtml(g) + '</option>'
            ).join('');
    }
    window.openSNIRuleModal = function () {
        editingSNIRuleName = null;
        document.getElementById("sni-rule-modal-title").textContent = "Add SNI Rule";
        document.getElementById("inp-sni-rule-name").value = "";
        document.getElementById("inp-sni-rule-name").disabled = false;
        document.getElementById("inp-sni-rule-action").value = "direct";
        populateSNIRuleGroupSelect("");
        document.getElementById("inp-sni-rule-domains").value = "";
        selectedRoutingPeers = {};
        renderRoutingPeerPicker("sni-rule-peer-picker");
        toggleSNIRuleAction();
        openModal("sni-rule-modal");
    };
    window.openSNIRuleEditModal = function (name) {
        if (!routingData) return;
        const rule = (routingData.sni_rules || []).find(r => r.name === name);
        if (!rule) return;
        editingSNIRuleName = name;
        document.getElementById("sni-rule-modal-title").textContent = "Edit SNI Rule";
        document.getElementById("inp-sni-rule-name").value = name;
        document.getElementById("inp-sni-rule-name").disabled = true;
        document.getElementById("inp-sni-rule-action").value = rule.action;
        populateSNIRuleGroupSelect(rule.upstream_group || "");
        document.getElementById("inp-sni-rule-domains").value = (rule.domains || []).join(", ");
        selectedRoutingPeers = {};
        (rule.peers || []).forEach(function (p) { selectedRoutingPeers[p] = true; });
        renderRoutingPeerPicker("sni-rule-peer-picker");
        toggleSNIRuleAction();
        openModal("sni-rule-modal");
    };
    window.closeSNIRuleModal = function () {
        closeModal("sni-rule-modal");
        editingSNIRuleName = null;
    };
    window.toggleSNIRuleAction = function () {
        const action = document.getElementById("inp-sni-rule-action").value;
        document.getElementById("sni-rule-upstream-group").style.display =
            action === "upstream" ? "" : "none";
    };
    window.saveSNIRule = function () {
        const name = document.getElementById("inp-sni-rule-name").value.trim();
        const action = document.getElementById("inp-sni-rule-action").value;
        const upstreamGroup = document.getElementById("inp-sni-rule-upstream-group").value.trim();
        const domainsRaw = document.getElementById("inp-sni-rule-domains").value.trim();

        if (!name) {
            haptic("notification", "error");
            return;
        }
        if (action === "upstream" && !upstreamGroup) {
            haptic("notification", "error");
            showToast("Upstream group required");
            return;
        }

        const domains = domainsRaw ? domainsRaw.split(",").map(s => s.trim()).filter(Boolean) : [];
        if (domains.length === 0) {
            haptic("notification", "error");
            showToast("Add at least one domain");
            return;
        }

        const body = {
            name,
            action,
            upstream_group: action === "upstream" ? upstreamGroup : "",
            domains,
            peers: Object.keys(selectedRoutingPeers),
        };

        if (editingSNIRuleName) {
            api("PUT", "/api/routing/sni-rules/" + encodeURIComponent(editingSNIRuleName), body).then(d => {
                if (d.error) {
                    haptic("notification", "error");
                    showToast(d.error, true);
                    return;
                }
                haptic("notification", "success");
                showToast('SNI rule "' + name + '" updated');
                closeSNIRuleModal();
                refreshRouting();
            });
        } else {
            api("POST", "/api/routing/sni-rules", body).then(d => {
                if (d.error) {
                    haptic("notification", "error");
                    showToast(d.error, true);
                    return;
                }
                haptic("notification", "success");
                showToast('SNI rule "' + name + '" added');
                closeSNIRuleModal();
                refreshRouting();
            });
        }
    };

    // --- Routing: Port Rule Modal (create + edit) ---
    function populatePortRuleGroupSelect(selected) {
        const sel = document.getElementById('inp-port-rule-upstream-group');
        const allGroups = [...new Set((statusData && statusData.upstreams || []).flatMap(u => u.groups || []))];
        sel.innerHTML = '<option value="">— Select group —</option>' +
            allGroups.map(g => '<option value="' + escapeHtml(g) + '"' +
                (selected === g ? ' selected' : '') + '>' + escapeHtml(g) + '</option>'
            ).join('');
    }
    window.openPortRuleModal = function () {
        editingPortRuleName = null;
        document.getElementById("port-rule-modal-title").textContent = "Add Port Rule";
        document.getElementById("inp-port-rule-name").value = "";
        document.getElementById("inp-port-rule-name").disabled = false;
        document.getElementById("inp-port-rule-action").value = "block";
        populatePortRuleGroupSelect("");
        document.getElementById("inp-port-rule-ports").value = "";
        selectedRoutingPeers = {};
        renderRoutingPeerPicker("port-rule-peer-picker");
        togglePortRuleAction();
        openModal("port-rule-modal");
    };
    window.openPortRuleEditModal = function (name) {
        if (!routingData) return;
        const rule = (routingData.port_rules || []).find(r => r.name === name);
        if (!rule) return;
        editingPortRuleName = name;
        document.getElementById("port-rule-modal-title").textContent = "Edit Port Rule";
        document.getElementById("inp-port-rule-name").value = name;
        document.getElementById("inp-port-rule-name").disabled = true;
        document.getElementById("inp-port-rule-action").value = rule.action;
        populatePortRuleGroupSelect(rule.upstream_group || "");
        document.getElementById("inp-port-rule-ports").value = (rule.ports || []).join(", ");
        selectedRoutingPeers = {};
        (rule.peers || []).forEach(function (p) { selectedRoutingPeers[p] = true; });
        renderRoutingPeerPicker("port-rule-peer-picker");
        togglePortRuleAction();
        openModal("port-rule-modal");
    };
    window.closePortRuleModal = function () {
        closeModal("port-rule-modal");
        editingPortRuleName = null;
    };
    window.togglePortRuleAction = function () {
        const action = document.getElementById("inp-port-rule-action").value;
        document.getElementById("port-rule-upstream-group").style.display =
            action === "upstream" ? "" : "none";
    };
    window.savePortRule = function () {
        const name = document.getElementById("inp-port-rule-name").value.trim();
        const action = document.getElementById("inp-port-rule-action").value;
        const upstreamGroup = document.getElementById("inp-port-rule-upstream-group").value.trim();
        const portsRaw = document.getElementById("inp-port-rule-ports").value.trim();

        if (!name) {
            haptic("notification", "error");
            return;
        }
        if (action === "upstream" && !upstreamGroup) {
            haptic("notification", "error");
            showToast("Upstream group required");
            return;
        }

        const ports = portsRaw ? portsRaw.split(",").map(s => s.trim()).filter(Boolean) : [];
        if (ports.length === 0) {
            haptic("notification", "error");
            showToast("Add at least one port or port range");
            return;
        }

        const body = {
            name,
            action,
            upstream_group: action === "upstream" ? upstreamGroup : "",
            ports,
            peers: Object.keys(selectedRoutingPeers),
        };

        if (editingPortRuleName) {
            api("PUT", "/api/routing/port-rules/" + encodeURIComponent(editingPortRuleName), body).then(d => {
                if (d.error) {
                    haptic("notification", "error");
                    showToast(d.error, true);
                    return;
                }
                haptic("notification", "success");
                showToast('Port rule "' + name + '" updated');
                closePortRuleModal();
                refreshRouting();
            });
        } else {
            api("POST", "/api/routing/port-rules", body).then(d => {
                if (d.error) {
                    haptic("notification", "error");
                    showToast(d.error, true);
                    return;
                }
                haptic("notification", "success");
                showToast('Port rule "' + name + '" added');
                closePortRuleModal();
                refreshRouting();
            });
        }
    };

    // --- Routing: Protocol Rule Modal (create + edit) ---
    var KNOWN_PROTOCOLS = [
        { id: "bittorrent", name: "BitTorrent", desc: "Peer-to-peer file sharing" },
    ];
    var selectedProtocols = {};

    function renderProtocolPicker() {
        var el = document.getElementById("protocol-rule-picker");
        el.innerHTML = KNOWN_PROTOCOLS.map(function (p) {
            var sel = selectedProtocols[p.id] ? " selected" : "";
            return '<div class="blocklist-item routing' + sel + '" data-proto="' + escapeHtml(p.id) + '" onclick="toggleProtocolItem(this)">' +
                '<div class="blocklist-item-cb"></div>' +
                '<div class="blocklist-item-text">' +
                '<div class="blocklist-item-name">' + escapeHtml(p.name) + '</div>' +
                '<div class="blocklist-item-desc">' + escapeHtml(p.desc) + '</div>' +
                '</div></div>';
        }).join('');
    }

    window.toggleProtocolItem = function (el) {
        var id = el.getAttribute("data-proto");
        if (selectedProtocols[id]) {
            delete selectedProtocols[id];
            el.classList.remove("selected");
        } else {
            selectedProtocols[id] = true;
            el.classList.add("selected");
        }
        haptic("selection");
    };

    function populateProtocolRuleGroupSelect(selected) {
        const sel = document.getElementById('inp-protocol-rule-upstream-group');
        const allGroups = [...new Set((statusData && statusData.upstreams || []).flatMap(u => u.groups || []))];
        sel.innerHTML = '<option value="">— Select group —</option>' +
            allGroups.map(g => '<option value="' + escapeHtml(g) + '"' +
                (selected === g ? ' selected' : '') + '>' + escapeHtml(g) + '</option>'
            ).join('');
    }
    window.openProtocolRuleModal = function () {
        editingProtocolRuleName = null;
        document.getElementById("protocol-rule-modal-title").textContent = "Add Protocol Rule";
        document.getElementById("inp-protocol-rule-name").value = "";
        document.getElementById("inp-protocol-rule-name").disabled = false;
        document.getElementById("inp-protocol-rule-action").value = "block";
        populateProtocolRuleGroupSelect("");
        selectedProtocols = {};
        renderProtocolPicker();
        selectedRoutingPeers = {};
        renderRoutingPeerPicker("protocol-rule-peer-picker");
        toggleProtocolRuleAction();
        openModal("protocol-rule-modal");
    };
    window.openProtocolRuleEditModal = function (name) {
        if (!routingData) return;
        const rule = (routingData.protocol_rules || []).find(r => r.name === name);
        if (!rule) return;
        editingProtocolRuleName = name;
        document.getElementById("protocol-rule-modal-title").textContent = "Edit Protocol Rule";
        document.getElementById("inp-protocol-rule-name").value = name;
        document.getElementById("inp-protocol-rule-name").disabled = true;
        document.getElementById("inp-protocol-rule-action").value = rule.action;
        populateProtocolRuleGroupSelect(rule.upstream_group || "");
        selectedProtocols = {};
        (rule.protocols || []).forEach(function (p) { selectedProtocols[p] = true; });
        renderProtocolPicker();
        selectedRoutingPeers = {};
        (rule.peers || []).forEach(function (p) { selectedRoutingPeers[p] = true; });
        renderRoutingPeerPicker("protocol-rule-peer-picker");
        toggleProtocolRuleAction();
        openModal("protocol-rule-modal");
    };
    window.closeProtocolRuleModal = function () {
        closeModal("protocol-rule-modal");
        editingProtocolRuleName = null;
    };
    window.toggleProtocolRuleAction = function () {
        const action = document.getElementById("inp-protocol-rule-action").value;
        document.getElementById("protocol-rule-upstream-group").style.display =
            action === "upstream" ? "" : "none";
    };
    window.saveProtocolRule = function () {
        const name = document.getElementById("inp-protocol-rule-name").value.trim();
        const action = document.getElementById("inp-protocol-rule-action").value;
        const upstreamGroup = document.getElementById("inp-protocol-rule-upstream-group").value.trim();
        if (!name) {
            haptic("notification", "error");
            return;
        }
        if (action === "upstream" && !upstreamGroup) {
            haptic("notification", "error");
            showToast("Upstream group required");
            return;
        }

        const protocols = Object.keys(selectedProtocols);
        if (protocols.length === 0) {
            haptic("notification", "error");
            showToast("Add at least one protocol");
            return;
        }

        const body = {
            name,
            action,
            upstream_group: action === "upstream" ? upstreamGroup : "",
            protocols,
            peers: Object.keys(selectedRoutingPeers),
        };

        if (editingProtocolRuleName) {
            api("PUT", "/api/routing/protocol-rules/" + encodeURIComponent(editingProtocolRuleName), body).then(d => {
                if (d.error) {
                    haptic("notification", "error");
                    showToast(d.error, true);
                    return;
                }
                haptic("notification", "success");
                showToast('Protocol rule "' + name + '" updated');
                closeProtocolRuleModal();
                refreshRouting();
            });
        } else {
            api("POST", "/api/routing/protocol-rules", body).then(d => {
                if (d.error) {
                    haptic("notification", "error");
                    showToast(d.error, true);
                    return;
                }
                haptic("notification", "success");
                showToast('Protocol rule "' + name + '" added');
                closeProtocolRuleModal();
                refreshRouting();
            });
        }
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
    // Check for invite token in URL or Telegram start_param
    function getInviteToken() {
        try {
            // Check tgWebAppStartParam (deep linking via startattach)
            var params = new URLSearchParams(location.search);
            var startParam = params.get('tgWebAppStartParam');
            if (startParam && startParam.indexOf('inv_') === 0) {
                return startParam.slice(4);
            }
            // Check Telegram WebApp start_param
            if (tg && tg.initDataUnsafe && tg.initDataUnsafe.start_param) {
                var sp = tg.initDataUnsafe.start_param;
                if (sp.indexOf('inv_') === 0) return sp.slice(4);
            }
            // Fallback: check ?invite= query param
            if (params.get('invite')) return params.get('invite');
            var hash = location.hash;
            if (hash && hash.indexOf('invite=') !== -1) {
                return hash.split('invite=')[1];
            }
        } catch (e) {}
        return null;
    }

    var pendingInviteToken = getInviteToken();

    // --- Admin page ---
    function populateAdminPage() {
        var user = tg && tg.initDataUnsafe && tg.initDataUnsafe.user;
        var avatarEl = document.getElementById("admin-avatar");
        var nameEl = document.getElementById("admin-name");
        var roleEl = document.getElementById("admin-role");
        if (user) {
            var fullName = user.first_name || "";
            if (user.last_name) fullName += " " + user.last_name;
            nameEl.textContent = fullName || "User";
            if (user.photo_url) {
                avatarEl.innerHTML = '<img src="' + escapeHtml(user.photo_url) + '" alt="">';
            } else {
                avatarEl.textContent = (user.first_name || "U").charAt(0).toUpperCase();
            }
        } else {
            nameEl.textContent = "User";
            avatarEl.textContent = "U";
        }
        roleEl.textContent = meData ? meData.role : "";
    }

    // --- Admin: Backup & Restore ---
    // --- Password Modal ---
    var passwordModalCallback = null;

    function openPasswordModal(title, label, callback) {
        document.getElementById("password-modal-title").textContent = title;
        document.getElementById("password-modal-label").textContent = label;
        document.getElementById("inp-modal-password").value = "";
        passwordModalCallback = callback;
        openModal("password-modal");
        setTimeout(function () { document.getElementById("inp-modal-password").focus(); }, 300);
    }
    window.closePasswordModal = function () {
        closeModal("password-modal");
        passwordModalCallback = null;
    };
    window.submitPasswordModal = function () {
        var pw = document.getElementById("inp-modal-password").value;
        closeModal("password-modal");
        if (passwordModalCallback) {
            var cb = passwordModalCallback;
            passwordModalCallback = null;
            cb(pw);
        }
    };

    function downloadBackup(password) {
        var url = "/api/backup";
        var params = [];
        if (password) params.push("password=" + encodeURIComponent(password));

        if (tg && tg.downloadFile) {
            params.push("_auth=" + encodeURIComponent(initData));
            var downloadUrl = location.origin + url + "?" + params.join("&");
            var fname = "bridge-backup.db";
            tg.downloadFile({ url: downloadUrl, file_name: fname }, function (accepted) {
                if (accepted) {
                    haptic("notification", "success");
                    showToast("Backup downloaded" + (password ? " (encrypted)" : ""));
                }
            });
            return;
        }

        if (params.length) url += "?" + params.join("&");
        fetch(url, {
            headers: { "X-Telegram-Init-Data": initData },
        })
            .then(function (r) {
                if (!r.ok) return r.json().then(function (d) { throw new Error(d.error || "backup failed"); });
                var cd = r.headers.get("Content-Disposition") || "";
                var match = cd.match(/filename=([^\s;]+)/);
                var fname = match ? match[1] : "bridge-backup.db";
                return r.blob().then(function (blob) { return { blob: blob, fname: fname }; });
            })
            .then(function (res) {
                var blobUrl = URL.createObjectURL(res.blob);
                var a = document.createElement("a");
                a.href = blobUrl;
                a.download = res.fname;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(blobUrl);
                haptic("notification", "success");
                showToast("Backup downloaded" + (password ? " (encrypted)" : ""));
            })
            .catch(function (err) {
                haptic("notification", "error");
                showToast(err.message, true);
            });
    }

    function backupDB() {
        haptic("impact", "medium");
        openPasswordModal("Backup Password", "Optional — leave empty for unencrypted backup", function (pw) {
            downloadBackup(pw);
        });
    }

    function restoreDB() {
        haptic("selection");
        if (!confirm("This will replace the current database. A backup of the existing database will be kept. Continue?")) return;
        document.getElementById("restore-file-input").click();
    }

    var resetPhrase = "";

    function generatePhrase() {
        var words = ["alpha", "bravo", "delta", "echo", "foxtrot", "gamma", "hotel", "india", "kilo", "lima", "oscar", "papa", "romeo", "sierra", "tango", "zulu"];
        var a = words[Math.floor(Math.random() * words.length)];
        var b = words[Math.floor(Math.random() * words.length)];
        var n = Math.floor(Math.random() * 90) + 10;
        return a + "-" + b + "-" + n;
    }

    window.restartInstance = function () {
        haptic("impact");
        if (!confirm("This will restart the bridge process. All active connections will be briefly interrupted. Continue?")) return;
        haptic("impact", "heavy");
        api("POST", "/api/restart")
            .then(function (d) {
                if (d.error) {
                    haptic("notification", "error");
                    showToast(d.error, true);
                    return;
                }
                haptic("notification", "success");
                showToast("Instance is restarting…");
            })
            .catch(function (err) {
                haptic("notification", "error");
                showToast(err.message, true);
            });
    };

    window.promptResetInstance = function () {
        haptic("impact");
        resetPhrase = generatePhrase();
        var msgEl = document.getElementById("reset-alert-message");
        msgEl.innerHTML = 'This will erase <strong>ALL</strong> data and re-populate from the initial configuration. This cannot be undone.<br><br>Type <span class="alert-phrase">' + resetPhrase + '</span> to confirm:<br><input class="alert-input" id="reset-phrase-input" autocomplete="off" spellcheck="false" placeholder="Type the phrase above">';
        document.getElementById("reset-confirm-btn").disabled = true;
        document.getElementById("reset-alert-overlay").classList.add("open");
        var inp = document.getElementById("reset-phrase-input");
        inp.addEventListener("input", function () {
            document.getElementById("reset-confirm-btn").disabled = inp.value.trim() !== resetPhrase;
        });
        setTimeout(function () { inp.focus(); }, 100);
    };

    window.closeResetAlert = function () {
        document.getElementById("reset-alert-overlay").classList.remove("open");
        resetPhrase = "";
    };

    window.confirmResetInstance = function () {
        var inp = document.getElementById("reset-phrase-input");
        if (!inp || inp.value.trim() !== resetPhrase) return;
        closeResetAlert();
        haptic("impact", "heavy");
        api("POST", "/api/reset")
            .then(function (d) {
                if (d.error) {
                    haptic("notification", "error");
                    showToast(d.error, true);
                    return;
                }
                haptic("notification", "success");
                showToast("Instance reset successfully");
                groupsLoaded = false;
                dnsLoaded = false;
                routingLoaded = false;
                usersLoaded = false;
                invitesLoaded = false;
                refresh();
            })
            .catch(function (err) {
                haptic("notification", "error");
                showToast(err.message, true);
            });
    };

    function uploadRestore(file, password) {
        var form = new FormData();
        form.append("file", file);
        if (password) form.append("password", password);
        fetch("/api/restore", {
            method: "POST",
            headers: { "X-Telegram-Init-Data": initData },
            body: form,
        })
            .then(function (r) { return r.json(); })
            .then(function (d) {
                if (d.encrypted) {
                    // Server detected encrypted backup, prompt for password.
                    openPasswordModal("Restore Password", "This backup is encrypted — enter password to decrypt", function (pw) {
                        if (!pw) { showToast("Password is required", true); return; }
                        uploadRestore(file, pw);
                    });
                    return;
                }
                if (d.error) {
                    haptic("notification", "error");
                    showToast(d.error, true);
                    return;
                }
                haptic("notification", "success");
                showToast("Database restored");
                refresh();
            })
            .catch(function (err) {
                haptic("notification", "error");
                showToast(err.message, true);
            });
    }

    function handleRestoreFile(input) {
        var file = input.files && input.files[0];
        if (!file) return;
        input.value = "";
        uploadRestore(file, "");
    }

    api("GET", "/api/me")
        .then((d) => {
            meData = d;
            if (d.role === "admin") document.body.classList.add("is-admin");
            document.getElementById("loading").style.display = "none";
            document.getElementById("app").style.display = "block";
            populateAdminPage();
            // Restore saved tab now that app is visible and admin-only tabs are shown
            try {
                const savedTab = sessionStorage.getItem("activeTab");
                if (savedTab) {
                    const tabEl = document.querySelector('.tab-item[data-page="' + savedTab + '"]');
                    if (tabEl && tabEl.offsetParent !== null) switchTab(savedTab);
                }
            } catch (e) {}
            refresh();
        })
        .catch((err) => {
            // If forbidden and we have an invite token, try to redeem it
            if (err.message === "forbidden" && pendingInviteToken) {
                api("POST", "/api/invite", { token: pendingInviteToken }).then(d => {
                    if (d.error) {
                        showToast(d.error, true);
                        return;
                    }
                    // Clean URL and reload
                    history.replaceState(null, '', location.pathname);
                    location.reload();
                }).catch(() => {});
                return;
            }
            document.getElementById("loading").textContent =
                "Failed to load: " + err.message;
        });

    // Auto-refresh
    setInterval(refresh, 30000);
}
