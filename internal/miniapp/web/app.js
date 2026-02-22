const tg = window.Telegram && window.Telegram.WebApp;

if (!tg || !tg.initData) {
    document.getElementById("unauthorized").style.display = "block";
    document.getElementById("app").style.display = "none";
} else {
    tg.ready();
    tg.expand();

    const initData = tg.initData;
    let data = null;
    let groupsData = null;
    let groupsLoaded = false;
    let dnsData = null;
    let dnsLoaded = false;
    let meData = null;

    function isAdmin() {
        return meData && meData.role === "admin";
    }

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

    function showTab(name) {
        const sections = ["peers", "upstreams", "proxies", "dns", "users"];
        document.querySelectorAll("#app > .tabs > .tab").forEach((t, i) => {
            t.classList.toggle("active", sections[i] === name);
        });
        document.querySelectorAll(".section").forEach((s) => {
            s.classList.toggle("active", s.id === name);
        });
        if (name === "users" && !usersLoaded) refreshUsers();
        if (name === "upstreams" && !groupsLoaded) refreshGroups();
        if (name === "dns" && !dnsLoaded) refreshDNS();
        try {
            sessionStorage.setItem("activeTab", name);
        } catch (e) {}
    }

    function showSubTab(showId, hideId, btn) {
        document.getElementById(showId).style.display = "";
        document.getElementById(hideId).style.display = "none";
        btn.parentElement
            .querySelectorAll(".tab")
            .forEach((t) => t.classList.remove("active"));
        btn.classList.add("active");
        if (showId === "upstream-groups-view" && !groupsLoaded) refreshGroups();
        try {
            sessionStorage.setItem("activeUpstreamSubTab", showId);
        } catch (e) {}
    }

    let activeProxySubTab = "mtproxy";
    function showProxySubTab(type) {
        activeProxySubTab = type;
        const subs = ["mtproxy", "socks5", "http", "https"];
        const container = document.querySelector("#proxies > .sub-tabs");
        container.querySelectorAll(".tab").forEach((t, i) => {
            t.classList.toggle("active", subs[i] === type);
        });
        subs.forEach((s) => {
            document.getElementById("proxy-sub-" + s).style.display =
                s === type ? "" : "none";
        });
        try {
            sessionStorage.setItem("activeProxySubTab", type);
        } catch (e) {}
    }

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
        if (!unix || unix <= 0) return "offline";
        const sec = Math.floor(Date.now() / 1000) - unix;
        if (sec < 180) return "online";
        return "recent";
    }

    function truncSecret(s) {
        let d = s;
        if (d.length === 34 && (d.startsWith("dd") || d.startsWith("ee")))
            d = d.slice(2);
        return d.length > 8 ? d.slice(0, 8) + "…" : d;
    }

    function copyText(text) {
        navigator.clipboard.writeText(text).then(() => {
            tg.showAlert("Copied!");
        });
    }

    function render() {
        if (!data) return;
        document.getElementById("loading").style.display = "none";
        document.getElementById("uptime").textContent =
            "⏱ " + formatDuration(data.daemon.uptime_seconds);

        // Peers
        const pl = document.getElementById("peers-list");
        if (!data.peers || data.peers.length === 0) {
            pl.innerHTML = '<div class="empty">No peers configured</div>';
        } else {
            pl.innerHTML = data.peers
                .map((p) => {
                    const status = peerStatusClass(p.last_handshake_unix);
                    const name = p.name || p.public_key.slice(0, 8) + "...";
                    const stats = [
                        {
                            icon: "↓",
                            val: formatBytes(p.rx_bytes),
                            lbl: "Down",
                        },
                        { icon: "↑", val: formatBytes(p.tx_bytes), lbl: "Up" },
                    ];
                    if (p.rx_total > 0) {
                        stats.push({
                            icon: "⬇",
                            val: formatBytes(p.rx_total),
                            lbl: "Σ Down",
                        });
                        stats.push({
                            icon: "⬆",
                            val: formatBytes(p.tx_total),
                            lbl: "Σ Up",
                        });
                    }
                    const esc = name.replace(/'/g, "\\'");
                    return `
      <div class="card">
        <div class="peer-card">
          <div class="peer-left">
            <div class="peer-name-row">
              <span class="status-dot ${status}"></span>
              <span class="name">${name}</span>
              <span class="handshake">${timeAgo(p.last_handshake_unix)}</span>
            </div>
            <div class="peer-stats">
              ${stats.map((s) => `<div class="peer-stat"><span class="ps-icon">${s.icon}</span><span class="ps-val">${s.val}</span><span class="ps-lbl">${s.lbl}</span></div>`).join("")}
              <div class="peer-stat" style="grid-column:1/-1"><span class="ps-icon">🌐</span><span class="ps-val">${p.allowed_ips || "—"}</span><span class="ps-lbl">IP</span></div>
            </div>
          </div>
          <div class="peer-right">
            <div class="peer-btn-row">
              <button class="peer-btn wide action" onclick="showPeerConf('${esc}')">🔧 Config</button>
              <button class="peer-btn sq action" onclick="copyPeerConf('${esc}')" title="Copy config">📋</button>
            </div>
            <div class="peer-btn-row">
              <button class="peer-btn wide action" onclick="showPeerQR('${esc}')">📱 QR Code</button>
              <button class="peer-btn sq action" onclick="copyPeerQR('${esc}')" title="Copy QR">📋</button>
            </div>
            <button class="peer-btn delete danger" style="margin-top:5px" onclick="deletePeer('${esc}')">🗑️ Delete</button>
          </div>
        </div>
      </div>`;
                })
                .join("");
        }

        // Upstreams
        const ul = document.getElementById("upstreams-list");
        if (!data.upstreams || data.upstreams.length === 0) {
            ul.innerHTML = '<div class="empty">No upstreams configured</div>';
        } else {
            ul.innerHTML = data.upstreams
                .map((u) => {
                    const stateIcon =
                        u.state === "healthy"
                            ? "🟢"
                            : u.state === "degraded"
                              ? "🟡"
                              : "🔴";
                    const badges = [];
                    if (u.default) badges.push("default");
                    if (!u.enabled) badges.push("disabled");
                    const badgeHtml = badges
                        .map((b) => `<span class="meta">(${b})</span>`)
                        .join(" ");
                    const groupsHtml =
                        u.groups && u.groups.length > 0
                            ? `<span>Groups: ${u.groups.join(", ")}</span>`
                            : "";
                    return `
      <div class="card">
        <div class="card-header">
          <span class="name">${stateIcon} ${u.name} <span class="meta">${u.type}</span> ${badgeHtml}</span>
          ${isAdmin() ? `<div style="display:flex;gap:4px">
            ${u.enabled ? `<button class="btn btn-sm" style="background:var(--hint)" onclick="toggleUpstream('${u.name}',false)">Disable</button>` : `<button class="btn btn-sm" onclick="toggleUpstream('${u.name}',true)">Enable</button>`}
            <button class="btn btn-sm btn-danger" onclick="deleteUpstream('${u.name}')">✕</button>
          </div>` : ""}
        </div>
        <div class="meta">
          <span>↓${formatBytes(u.rx_bytes)} ↑${formatBytes(u.tx_bytes)}</span>
          <span>Conns: ${u.active_connections}</span>
        </div>
        ${groupsHtml ? `<div class="meta">${groupsHtml}</div>` : ""}
        ${u.last_error ? `<div class="error-msg">${u.last_error}</div>` : ""}
      </div>`;
                })
                .join("");
        }

        // MTProxy
        const ms = document.getElementById("mtproxy-status");
        if (!data.mtproxy.enabled) {
            ms.innerHTML = '<div class="empty">MTProxy not enabled</div>';
            document.getElementById("proxy-links").innerHTML = "";
        } else {
            const tiles = [
                {
                    icon: "⚡",
                    value: data.mtproxy.active_connections,
                    label: "Active",
                },
                {
                    icon: "🔗",
                    value: data.mtproxy.connections,
                    label: "Session",
                },
                {
                    icon: "↑",
                    value: formatBytes(data.mtproxy.bytes_c2b),
                    label: "Upload",
                },
                {
                    icon: "↓",
                    value: formatBytes(data.mtproxy.bytes_b2c),
                    label: "Download",
                },
            ];
            if (data.mtproxy.bytes_c2b_total > 0) {
                tiles.push({
                    icon: "⬆",
                    value: formatBytes(data.mtproxy.bytes_c2b_total),
                    label: "Total Up",
                });
                tiles.push({
                    icon: "⬇",
                    value: formatBytes(data.mtproxy.bytes_b2c_total),
                    label: "Total Down",
                });
            }
            ms.innerHTML = `<div class="card"><div class="stats-grid">${tiles
                .map(
                    (t) =>
                        `<div class="stat-tile">
        <span class="stat-icon">${t.icon}</span>
        <span class="stat-value">${t.value}</span>
        <span class="stat-label">${t.label}</span>
      </div>`,
                )
                .join("")}</div></div>`;

            const ll = document.getElementById("proxy-links");
            const secretMap = {};
            (data.mtproxy.secrets || []).forEach((s) => {
                secretMap[s.secret] = s;
            });

            function secretTypeBadge(secret) {
                if (secret.startsWith("ee"))
                    return '<span title="FakeTLS" style="cursor:default">🛡️</span>';
                if (secret.startsWith("dd"))
                    return '<span title="Padded" style="cursor:default">📦</span>';
                return '<span title="Basic" style="cursor:default">🔓</span>';
            }

            if (data.mtproxy.links && data.mtproxy.links.length > 0) {
                ll.innerHTML =
                    '<hr style="border:none;border-top:1px solid color-mix(in srgb,var(--hint) 30%,transparent);margin:12px 0"><h2>🔗 Proxy Links</h2>' +
                    data.mtproxy.links
                        .map((l) => {
                            const s = secretMap[l.secret];
                            const statsHtml = s
                                ? `<div class="meta">
            <span>Last: ${timeAgo(s.last_connection_unix)}</span>
            <span>Conns: ${s.connections}${s.connections_total > 0 ? " / " + s.connections_total + " total" : ""}</span>
          </div>`
                                : "";
                            return `
        <div class="card" id="plink-${l.secret}">
          <div class="proxy-link-card">
            <span class="name"${isAdmin() ? ` onclick="startRenameLink('${l.secret}', this)"` : ""}>${secretTypeBadge(l.secret)} ${l.name}</span>
            ${isAdmin() ? `<button class="icon-btn" onclick="startRenameLink('${l.secret}', this.parentElement.querySelector('.name'))" title="Rename">✏️</button>` : ""}
            <button class="icon-btn" onclick="copyText('${l.url}')" title="Copy link">📋</button>
            <a class="icon-btn" href="${l.url}" target="_blank" title="Open link">🔗</a>
            <button class="icon-btn" onclick="deleteSecret('${l.secret}')" title="Delete secret" style="color:#e53935">🗑️</button>
          </div>
          ${statsHtml}
        </div>`;
                        })
                        .join("");
            } else {
                ll.innerHTML = '<div class="empty">No secrets</div>';
            }
        }

        // Proxies (per-type sub-tabs)
        ["socks5", "http", "https"].forEach((type) => {
            const el = document.getElementById("proxies-list-" + type);
            const filtered = (data.proxies || []).filter(
                (p) => p.type === type,
            );
            if (filtered.length === 0) {
                el.innerHTML =
                    '<div class="empty">No ' +
                    type.toUpperCase() +
                    " proxies</div>";
            } else {
                el.innerHTML = filtered
                    .map(
                        (p) => `
        <div class="card">
          <div class="card-header">
            <span class="name">${p.name}</span>
            <button class="btn btn-sm btn-danger" onclick="deleteProxy('${p.name}')">Delete</button>
          </div>
          <div class="meta">
            <span>Listen: ${p.listen}</span>
            ${p.has_auth ? "<span>🔒 Auth</span>" : ""}
          </div>
          <div class="meta">
            <span class="link-text">${p.link}</span>
            <button class="copy-btn" onclick="copyText('${p.link}')">📋</button>
          </div>
        </div>
      `,
                    )
                    .join("");
            }
        });
    }

    function refresh() {
        api("GET", "/api/status")
            .then((d) => {
                data = d;
                render();
                if (groupsLoaded) refreshGroups();
            })
            .catch((err) => {
                document.getElementById("loading").textContent =
                    "Error: " + err.message;
            });
    }

    function showMsg(id, text, isError) {
        const el = document.getElementById(id);
        el.className = isError ? "error-msg" : "success-msg";
        el.textContent = text;
        setTimeout(() => {
            el.textContent = "";
        }, 3000);
    }

    function fetchPeerConf(name) {
        return api("GET", "/api/peers/" + encodeURIComponent(name) + "/conf");
    }

    function showPeerConf(name) {
        fetchPeerConf(name).then((d) => {
            if (d.error) {
                showMsg("peer-msg", d.error, true);
                return;
            }
            const overlay = document.createElement("div");
            overlay.className = "modal-overlay";
            overlay.onclick = (e) => {
                if (e.target === overlay) overlay.remove();
            };
            overlay.innerHTML = `
      <div class="modal-content">
        <div class="modal-header">
          <span class="name">📋 ${name}</span>
          <button class="modal-close" onclick="this.closest('.modal-overlay').remove()">✕</button>
        </div>
        <pre>${d.config}</pre>
        <div class="btn-row" style="justify-content:center">
          <button class="btn btn-sm" onclick="copyText(this.closest('.modal-content').querySelector('pre').textContent)">📄 Copy</button>
        </div>
      </div>`;
            document.body.appendChild(overlay);
        });
    }

    function copyPeerConf(name) {
        fetchPeerConf(name).then((d) => {
            if (d.error) {
                showMsg("peer-msg", d.error, true);
                return;
            }
            copyText(d.config);
        });
    }

    function showPeerQR(name) {
        fetchPeerConf(name).then((d) => {
            if (d.error) {
                showMsg("peer-msg", d.error, true);
                return;
            }
            const overlay = document.createElement("div");
            overlay.className = "modal-overlay";
            overlay.onclick = (e) => {
                if (e.target === overlay) overlay.remove();
            };
            overlay.innerHTML = `
      <div class="modal-content">
        <div class="modal-header">
          <span class="name">📱 ${name}</span>
          <button class="modal-close" onclick="this.closest('.modal-overlay').remove()">✕</button>
        </div>
        <div id="qr-container" style="display:flex;justify-content:center"></div>
        <div class="btn-row" style="justify-content:center">
          <button class="btn btn-sm" onclick="copyQRFromModal()">🖼️ Copy QR</button>
        </div>
      </div>`;
            document.body.appendChild(overlay);
            new QRCode(document.getElementById("qr-container"), {
                text: d.config,
                width: 280,
                height: 280,
                colorDark: "#000000",
                colorLight: "#ffffff",
                correctLevel: QRCode.CorrectLevel.M,
            });
        });
    }

    function copyPeerQR(name) {
        fetchPeerConf(name).then((d) => {
            if (d.error) {
                showMsg("peer-msg", d.error, true);
                return;
            }
            const tmp = document.createElement("div");
            tmp.style.position = "absolute";
            tmp.style.left = "-9999px";
            document.body.appendChild(tmp);
            new QRCode(tmp, {
                text: d.config,
                width: 280,
                height: 280,
                colorDark: "#000000",
                colorLight: "#ffffff",
                correctLevel: QRCode.CorrectLevel.M,
            });
            setTimeout(() => {
                const canvas = tmp.querySelector("canvas");
                if (canvas) {
                    canvas.toBlob((blob) => {
                        navigator.clipboard
                            .write([new ClipboardItem({ "image/png": blob })])
                            .then(() => {
                                tg.showAlert("QR code copied!");
                            })
                            .catch(() => {
                                tg.showAlert("Could not copy QR code");
                            });
                        tmp.remove();
                    });
                } else {
                    tmp.remove();
                    tg.showAlert("Could not generate QR code");
                }
            }, 100);
        });
    }

    function copyQRFromModal() {
        const container = document.getElementById("qr-container");
        if (!container) return;
        const canvas = container.querySelector("canvas");
        if (!canvas) return;
        canvas.toBlob((blob) => {
            navigator.clipboard
                .write([new ClipboardItem({ "image/png": blob })])
                .then(() => {
                    tg.showAlert("QR code copied!");
                })
                .catch(() => {
                    tg.showAlert("Could not copy QR code");
                });
        });
    }

    function addPeer() {
        const name = document.getElementById("new-peer-name").value.trim();
        if (!name) return;
        api("POST", "/api/peers", { name }).then((d) => {
            if (d.error) {
                showMsg("peer-msg", d.error, true);
                return;
            }
            document.getElementById("new-peer-name").value = "";
            showMsg("peer-msg", 'Peer "' + name + '" added', false);
            refresh();
        });
    }

    function deletePeer(name) {
        tg.showConfirm('Delete peer "' + name + '"?', (ok) => {
            if (!ok) return;
            api("DELETE", "/api/peers/" + encodeURIComponent(name)).then(
                (d) => {
                    if (d.error) {
                        showMsg("peer-msg", d.error, true);
                        return;
                    }
                    refresh();
                },
            );
        });
    }

    function addSecret() {
        const type = document.getElementById("new-secret-type").value;
        api("POST", "/api/secrets", { type }).then((d) => {
            if (d.error) {
                showMsg("secret-msg", d.error, true);
                return;
            }
            showMsg(
                "secret-msg",
                "Secret added (send SIGHUP to reload)",
                false,
            );
            refresh();
        });
    }

    function startRenameLink(secret, nameEl) {
        const card = document.getElementById("plink-" + secret);
        if (!card || card.querySelector(".rename-form")) return;
        const oldName = nameEl.textContent.replace(/^[🛡️📦🔓]\s*/u, "");
        const form = document.createElement("div");
        form.className = "rename-form";
        const input = document.createElement("input");
        input.type = "text";
        input.value = oldName;
        const okBtn = document.createElement("button");
        okBtn.className = "icon-btn-sm";
        okBtn.textContent = "✅";
        okBtn.title = "Apply";
        const cancelBtn = document.createElement("button");
        cancelBtn.className = "icon-btn-sm";
        cancelBtn.textContent = "❌";
        cancelBtn.title = "Cancel";
        form.appendChild(input);
        form.appendChild(okBtn);
        form.appendChild(cancelBtn);

        nameEl.style.display = "none";
        const editBtn = card.querySelector('.icon-btn[title="Rename"]');
        if (editBtn) editBtn.style.display = "none";
        nameEl.parentElement.insertBefore(form, nameEl);
        input.focus();
        input.select();

        function apply() {
            const newName = input.value.trim();
            if (!newName || newName === oldName) {
                cancel();
                return;
            }
            api("PUT", "/api/secrets/" + encodeURIComponent(secret) + "/name", {
                name: newName,
            }).then((d) => {
                if (d.error) {
                    tg.showAlert(d.error);
                    cancel();
                    return;
                }
                refresh();
            });
        }
        function cancel() {
            form.remove();
            nameEl.style.display = "";
            if (editBtn) editBtn.style.display = "";
        }
        okBtn.addEventListener("click", apply);
        cancelBtn.addEventListener("click", cancel);
        input.addEventListener("keydown", (e) => {
            if (e.key === "Enter") {
                e.preventDefault();
                apply();
            }
            if (e.key === "Escape") {
                e.preventDefault();
                cancel();
            }
        });
    }

    function deleteSecret(hex) {
        tg.showConfirm("Delete this secret?", (ok) => {
            if (!ok) return;
            api("DELETE", "/api/secrets/" + encodeURIComponent(hex)).then(
                (d) => {
                    if (d.error) {
                        showMsg("secret-msg", d.error, true);
                        return;
                    }
                    showMsg(
                        "secret-msg",
                        "Secret deleted (send SIGHUP to reload)",
                        false,
                    );
                    refresh();
                },
            );
        });
    }

    function addProxyTyped(type) {
        const listen = document
            .getElementById("new-proxy-listen-" + type)
            .value.trim();
        const name = document
            .getElementById("new-proxy-name-" + type)
            .value.trim();
        if (!listen) return;
        api("POST", "/api/proxies", {
            type,
            listen,
            name: name || undefined,
        }).then((d) => {
            if (d.error) {
                showMsg("proxy-msg-" + type, d.error, true);
                return;
            }
            document.getElementById("new-proxy-listen-" + type).value = "";
            document.getElementById("new-proxy-name-" + type).value = "";
            showMsg(
                "proxy-msg-" + type,
                "Proxy added (restart required)",
                false,
            );
            refresh();
        });
    }

    function deleteProxy(name) {
        tg.showConfirm('Delete proxy "' + name + '"?', (ok) => {
            if (!ok) return;
            api("DELETE", "/api/proxies/" + encodeURIComponent(name)).then(
                (d) => {
                    const msgId = "proxy-msg-" + activeProxySubTab;
                    if (d.error) {
                        showMsg(msgId, d.error, true);
                        return;
                    }
                    showMsg(msgId, "Proxy deleted (restart required)", false);
                    refresh();
                },
            );
        });
    }

    // Upstreams
    function addUpstream() {
        const name = document.getElementById("new-upstream-name").value.trim();
        const type = document.getElementById("new-upstream-type").value;
        const transport = document
            .getElementById("new-upstream-transport")
            .value.trim();
        const isDefault = document.getElementById(
            "new-upstream-default",
        ).checked;
        const hcEnabled = document.getElementById("new-upstream-hc").checked;
        if (!name || !transport) return;
        api("POST", "/api/upstreams", {
            name,
            type,
            transport,
            default: isDefault,
            health_check: {
                enabled: hcEnabled,
                interval: 30,
                target: "1.1.1.1:80",
            },
        }).then((d) => {
            if (d.error) {
                showMsg("upstream-msg", d.error, true);
                return;
            }
            document.getElementById("new-upstream-name").value = "";
            document.getElementById("new-upstream-transport").value = "";
            document.getElementById("new-upstream-default").checked = false;
            showMsg("upstream-msg", 'Upstream "' + name + '" added', false);
            refresh();
        });
    }

    function deleteUpstream(name) {
        tg.showConfirm('Delete upstream "' + name + '"?', (ok) => {
            if (!ok) return;
            api("DELETE", "/api/upstreams/" + encodeURIComponent(name)).then(
                (d) => {
                    if (d.error) {
                        showMsg("upstream-msg", d.error, true);
                        return;
                    }
                    showMsg("upstream-msg", "Upstream deleted", false);
                    refresh();
                },
            );
        });
    }

    function toggleUpstream(name, enable) {
        api("PUT", "/api/upstreams/" + encodeURIComponent(name), {
            enabled: enable,
        }).then((d) => {
            if (d.error) {
                showMsg("upstream-msg", d.error, true);
                return;
            }
            refresh();
        });
    }

    // Users
    let usersLoaded = false;
    let usersData = [];

    function refreshUsers() {
        api("GET", "/api/users").then((d) => {
            usersData = d;
            usersLoaded = true;
            renderUsers();
        });
    }

    function renderMe() {
        const el = document.getElementById("current-user");
        if (!meData || !el) return;
        const roleBadge = meData.role === "admin" ? "👑 Admin" : "👤 Guest";
        el.textContent = roleBadge;
        updateTabVisibility();
    }

    function updateTabVisibility() {
        const admin = isAdmin();
        const sections = ["peers", "upstreams", "proxies", "dns", "users"];
        const adminOnlyTabs = ["upstreams", "dns", "users"];
        document.querySelectorAll("#app > .tabs > .tab").forEach((t, i) => {
            if (adminOnlyTabs.includes(sections[i])) {
                t.style.display = admin ? "" : "none";
            }
        });
        // Toggle admin-only elements throughout the page
        document.querySelectorAll(".admin-only").forEach((el) => {
            el.style.display = admin ? "" : "none";
        });
        // For guests, hide non-mtproxy proxy sub-tabs and force mtproxy view
        const proxySubTabs = document.querySelectorAll("#proxies > .sub-tabs > .tab");
        const adminOnlyProxySubs = ["socks5", "http", "https"];
        const proxySubs = ["mtproxy", "socks5", "http", "https"];
        proxySubTabs.forEach((t, i) => {
            if (adminOnlyProxySubs.includes(proxySubs[i])) {
                t.style.display = admin ? "" : "none";
            }
        });
        if (!admin) {
            showProxySubTab("mtproxy");
        }
        // If guest is on a hidden tab, switch to peers
        if (!admin) {
            try {
                const active = sessionStorage.getItem("activeTab");
                if (active && adminOnlyTabs.includes(active)) {
                    showTab("peers");
                }
            } catch (e) {}
        }
        // Re-render to update inline admin controls
        if (data) render();
        if (dnsData) renderDNS();
    }

    function renderUsers() {
        const ul = document.getElementById("users-list");
        if (!usersData || usersData.length === 0) {
            ul.innerHTML =
                '<div class="empty">No additional users granted access</div>';
            return;
        }
        ul.innerHTML = usersData
            .map((u) => {
                const name =
                    [u.first_name, u.last_name].filter(Boolean).join(" ") ||
                    (u.is_admin ? "Admin (ID: " + u.user_id + ")" : "Unknown");
                const avatar = u.photo_url
                    ? `<img src="${u.photo_url}" style="width:36px;height:36px;border-radius:50%;object-fit:cover;">`
                    : `<div style="width:36px;height:36px;border-radius:50%;background:var(--btn);display:flex;align-items:center;justify-content:center;font-size:16px;color:var(--btn-text)">${(u.first_name || "?")[0]}</div>`;
                const isConfigAdmin = u.is_config_admin;
                let roleHtml;
                if (isConfigAdmin) {
                    roleHtml = '<span style="background:var(--btn);color:var(--btn-text);font-size:10px;padding:1px 6px;border-radius:4px;margin-left:6px">admin</span>';
                } else {
                    const role = u.role || (u.is_admin ? "admin" : "guest");
                    roleHtml = `<select class="role-select" onchange="changeUserRole(${u.user_id},this.value)" style="font-size:10px;padding:1px 4px;border-radius:4px;margin-left:6px;background:var(--bg);color:var(--text);border:1px solid var(--hint)">
                        <option value="admin"${role === "admin" ? " selected" : ""}>admin</option>
                        <option value="guest"${role === "guest" ? " selected" : ""}>guest</option>
                    </select>`;
                }
                const deleteBtn = isConfigAdmin
                    ? ""
                    : `<button class="btn btn-sm btn-danger" onclick="deleteUser(${u.user_id},'${name.replace(/'/g, "\\'")}')">✕</button>`;
                return `
      <div class="card" style="display:flex;align-items:center;gap:10px">
        ${avatar}
        <div style="flex:1;min-width:0">
          <div class="name">${name}${roleHtml}</div>
          <div class="meta">${u.username ? "@" + u.username : ""} · ID: ${u.user_id}</div>
        </div>
        ${deleteBtn}
      </div>`;
            })
            .join("");
    }

    function changeUserRole(userId, role) {
        api("PUT", "/api/users/" + userId, { role: role }).then((d) => {
            if (d.error) {
                showMsg("user-msg", d.error, true);
                refreshUsers();
                return;
            }
            showMsg("user-msg", "Role updated", false);
            refreshUsers();
        });
    }

    function addUser() {
        const input = document.getElementById("new-user").value.trim();
        if (!input) return;
        api("POST", "/api/users", { user: input }).then((d) => {
            if (d.error) {
                showMsg("user-msg", d.error, true);
                return;
            }
            document.getElementById("new-user").value = "";
            showMsg("user-msg", "User added", false);
            refreshUsers();
        });
    }

    function deleteUser(id, name) {
        tg.showConfirm('Revoke access for "' + name + '"?', (ok) => {
            if (!ok) return;
            api("DELETE", "/api/users/" + id).then((d) => {
                if (d.error) {
                    showMsg("user-msg", d.error, true);
                    return;
                }
                showMsg("user-msg", "Access revoked", false);
                refreshUsers();
            });
        });
    }

    // DNS
    function refreshDNS() {
        api("GET", "/api/dns").then((d) => {
            dnsData = d;
            dnsLoaded = true;
            renderDNS();
        });
    }

    function renderDNS() {
        if (!dnsData) return;

        // Status card
        const ds = document.getElementById("dns-status");
        if (!dnsData.enabled) {
            ds.innerHTML = '<div class="empty">DNS proxy not enabled</div>';
            document.getElementById("dns-records").innerHTML = "";
            document.getElementById("dns-rules").innerHTML = "";
            return;
        }

        ds.innerHTML = `<div class="card">
    <div class="card-header">
      <span class="name">🔍 DNS Proxy</span>
      <span style="color:#4caf50;font-size:12px">● Enabled</span>
    </div>
    <div class="meta">
      <span>Listen: ${dnsData.listen}</span>
      <span>Upstream: ${dnsData.upstream}</span>
    </div>
  </div>`;

        // Records
        const rl = document.getElementById("dns-records");
        if (!dnsData.records || dnsData.records.length === 0) {
            rl.innerHTML =
                '<h2>📋 Static Records</h2><div class="empty">No static records configured</div>';
        } else {
            rl.innerHTML =
                "<h2>📋 Static Records</h2>" +
                dnsData.records
                    .map(
                        (r) => `
      <div class="card">
        <div class="card-header">
          <span class="name" style="font-family:monospace;font-size:13px">${r.name}</span>
          <span class="meta">TTL: ${r.ttl || 60}s</span>
        </div>
        <div class="meta">
          ${r.a && r.a.length > 0 ? "<span>A: " + r.a.join(", ") + "</span>" : ""}
          ${r.aaaa && r.aaaa.length > 0 ? "<span>AAAA: " + r.aaaa.join(", ") + "</span>" : ""}
        </div>
      </div>
    `,
                    )
                    .join("");
        }

        // Rules
        const ul = document.getElementById("dns-rules");
        if (!dnsData.rules || dnsData.rules.length === 0) {
            ul.innerHTML =
                '<h2>📜 Rules</h2><div class="empty">No DNS rules configured</div>';
        } else {
            ul.innerHTML =
                "<h2>📜 Rules</h2>" +
                dnsData.rules
                    .map((r) => {
                        const actionIcon = r.action === "block" ? "🚫" : "↗️";
                        const actionLabel =
                            r.action === "block"
                                ? "Block"
                                : "Upstream: " + r.upstream;
                        const domainsHtml =
                            r.domains && r.domains.length > 0
                                ? '<div class="meta" style="margin-top:4px"><span>Domains: ' +
                                  r.domains
                                      .map(
                                          (d) =>
                                              '<code style="background:var(--bg);padding:1px 4px;border-radius:3px;font-size:11px">' +
                                              d +
                                              "</code>",
                                      )
                                      .join(" ") +
                                  "</span></div>"
                                : "";
                        const listsHtml =
                            r.lists && r.lists.length > 0
                                ? '<div class="meta" style="margin-top:4px">' +
                                  r.lists
                                      .map(
                                          (l) =>
                                              "<div><span>📥 " +
                                              l.url +
                                              '</span><span class="meta"> (' +
                                              (l.format || "domains") +
                                              ", refresh: " +
                                              formatRefresh(l.refresh) +
                                              ")</span></div>",
                                      )
                                      .join("") +
                                  "</div>"
                                : "";
                        const escapedName = r.name.replace(/'/g, "\\'");
                        return `
      <div class="card">
        <div class="card-header">
          <span class="name">${actionIcon} ${r.name}</span>
          <div style="display:flex;align-items:center;gap:6px">
            <span class="meta">${actionLabel}</span>
            ${isAdmin() ? `<button class="btn btn-sm btn-danger" onclick="deleteDNSRule('${escapedName}')">✕</button>` : ""}
          </div>
        </div>
        ${domainsHtml}
        ${listsHtml}
      </div>`;
                    })
                    .join("");
        }
    }

    function dnsActionChanged() {
        const action = document.getElementById("new-dns-rule-action").value;
        document.getElementById("dns-upstream-row").style.display =
            action === "upstream" ? "" : "none";
    }

    function addDNSRule() {
        const name = document.getElementById("new-dns-rule-name").value.trim();
        const action = document.getElementById("new-dns-rule-action").value;
        const upstream = document
            .getElementById("new-dns-rule-upstream")
            .value.trim();
        const domainsRaw = document
            .getElementById("new-dns-rule-domains")
            .value.trim();
        const listUrl = document
            .getElementById("new-dns-rule-list-url")
            .value.trim();
        const listFormat = document.getElementById(
            "new-dns-rule-list-format",
        ).value;

        if (!name) return;

        const domains = domainsRaw
            ? domainsRaw
                  .split(",")
                  .map((d) => d.trim())
                  .filter(Boolean)
            : [];
        const lists = [];
        if (listUrl) {
            lists.push({ url: listUrl, format: listFormat, refresh: 86400 });
        }

        if (domains.length === 0 && lists.length === 0) {
            showMsg(
                "dns-msg",
                "At least one domain or blocklist URL is required",
                true,
            );
            return;
        }

        const body = { name, action, domains, lists };
        if (action === "upstream") body.upstream = upstream;

        api("POST", "/api/dns", body).then((d) => {
            if (d.error) {
                showMsg("dns-msg", d.error, true);
                return;
            }
            document.getElementById("new-dns-rule-name").value = "";
            document.getElementById("new-dns-rule-upstream").value = "";
            document.getElementById("new-dns-rule-domains").value = "";
            document.getElementById("new-dns-rule-list-url").value = "";
            showMsg("dns-msg", 'Rule "' + name + '" added', false);
            refreshDNS();
        });
    }

    function deleteDNSRule(name) {
        tg.showConfirm('Delete DNS rule "' + name + '"?', (ok) => {
            if (!ok) return;
            api("DELETE", "/api/dns/rules/" + encodeURIComponent(name)).then(
                (d) => {
                    if (d.error) {
                        showMsg("dns-msg", d.error, true);
                        return;
                    }
                    showMsg("dns-msg", "Rule deleted", false);
                    refreshDNS();
                },
            );
        });
    }

    function formatRefresh(seconds) {
        if (!seconds) return "24h";
        if (seconds >= 86400) return Math.floor(seconds / 86400) + "d";
        if (seconds >= 3600) return Math.floor(seconds / 3600) + "h";
        if (seconds >= 60) return Math.floor(seconds / 60) + "m";
        return seconds + "s";
    }

    // Groups
    function refreshGroups() {
        api("GET", "/api/groups").then((d) => {
            groupsData = d;
            groupsLoaded = true;
            renderGroups();
        });
    }

    function renderGroups() {
        if (!groupsData) return;
        const gl = document.getElementById("groups-list");
        if (!groupsData || groupsData.length === 0) {
            gl.innerHTML = '<div class="empty">No groups found</div>';
        } else {
            gl.innerHTML = groupsData
                .map((g) => {
                    const membersHtml =
                        g.members && g.members.length > 0
                            ? g.members
                                  .map((m) => {
                                      const stateIcon =
                                          m.state === "healthy"
                                              ? "🟢"
                                              : m.state === "degraded"
                                                ? "🟡"
                                                : "🔴";
                                      const disabledTag = !m.enabled
                                          ? ' <span class="meta">(disabled)</span>'
                                          : "";
                                      return `<div style="display:flex;align-items:center;justify-content:space-between;padding:2px 0">
              <span>${stateIcon} ${m.name} <span class="meta">${m.type}</span>${disabledTag}</span>
              <button class="btn btn-sm btn-danger" style="padding:2px 6px;font-size:11px" onclick="removeFromGroup('${m.name}','${g.name}')">✕</button>
            </div>`;
                                  })
                                  .join("")
                            : '<div class="meta" style="padding:2px 0">No members</div>';
                    const consumersHtml =
                        g.consumers && g.consumers.length > 0
                            ? g.consumers
                                  .map((c) => {
                                      const icon =
                                          c.type === "proxy"
                                              ? "🔌"
                                              : c.type === "mtproxy"
                                                ? "📡"
                                                : c.type === "ip_rule"
                                                  ? "🌐"
                                                  : "🔗";
                                      return `<span class="meta" style="margin-right:8px">${icon} ${c.name} (${c.type})</span>`;
                                  })
                                  .join("")
                            : "";
                    return `
      <div class="card">
        <div class="card-header">
          <span class="name">📦 ${g.name}</span>
          <span class="meta">${g.members ? g.members.length : 0} member${g.members && g.members.length !== 1 ? "s" : ""}</span>
        </div>
        <div style="margin:4px 0">${membersHtml}</div>
        ${consumersHtml ? `<div style="margin-top:4px;padding-top:4px;border-top:1px solid var(--hint)">${consumersHtml}</div>` : ""}
      </div>`;
                })
                .join("");
        }

        // Populate upstream select for the "assign" form
        const sel = document.getElementById("group-upstream-select");
        const currentVal = sel.value;
        sel.innerHTML = '<option value="">Select upstream…</option>';
        if (data && data.upstreams) {
            data.upstreams.forEach((u) => {
                sel.innerHTML += `<option value="${u.name}">${u.name}</option>`;
            });
        }
        sel.value = currentVal;
    }

    function addToGroup() {
        const upstreamName = document.getElementById(
            "group-upstream-select",
        ).value;
        const groupName = document
            .getElementById("group-name-input")
            .value.trim();
        if (!upstreamName || !groupName) return;
        // Find the upstream's current groups from the status data
        const upstream = data.upstreams.find((u) => u.name === upstreamName);
        if (!upstream) return;
        // Get the upstream's custom groups (filter out implicit ones)
        const currentGroups = (upstream.groups || []).filter(
            (g) => g !== "default" && !g.startsWith("upstream:"),
        );
        if (currentGroups.includes(groupName)) {
            showMsg(
                "group-msg",
                'Upstream already in group "' + groupName + '"',
                true,
            );
            return;
        }
        const newGroups = [...currentGroups, groupName];
        api("PUT", "/api/upstreams/" + encodeURIComponent(upstreamName), {
            groups: newGroups,
        }).then((d) => {
            if (d.error) {
                showMsg("group-msg", d.error, true);
                return;
            }
            document.getElementById("group-name-input").value = "";
            showMsg(
                "group-msg",
                upstreamName + ' added to group "' + groupName + '"',
                false,
            );
            refresh();
        });
    }

    function removeFromGroup(upstreamName, groupName) {
        // Cannot remove the implicit upstream:<name> group
        if (groupName.startsWith("upstream:")) {
            showMsg(
                "group-msg",
                'Cannot remove implicit group "' + groupName + '"',
                true,
            );
            return;
        }
        const upstream = data.upstreams.find((u) => u.name === upstreamName);
        if (!upstream) return;
        // Removing from "default" means unsetting the default flag
        if (groupName === "default") {
            api("PUT", "/api/upstreams/" + encodeURIComponent(upstreamName), {
                default: false,
            }).then((d) => {
                if (d.error) {
                    showMsg("group-msg", d.error, true);
                    return;
                }
                showMsg(
                    "group-msg",
                    upstreamName + ' removed from group "default"',
                    false,
                );
                refresh();
            });
            return;
        }
        const currentGroups = (upstream.groups || []).filter(
            (g) => g !== "default" && !g.startsWith("upstream:"),
        );
        const newGroups = currentGroups.filter((g) => g !== groupName);
        api("PUT", "/api/upstreams/" + encodeURIComponent(upstreamName), {
            groups: newGroups,
        }).then((d) => {
            if (d.error) {
                showMsg("group-msg", d.error, true);
                return;
            }
            showMsg(
                "group-msg",
                upstreamName + ' removed from group "' + groupName + '"',
                false,
            );
            refresh();
        });
    }

    // Restore active tab from session on reload.
    try {
        const savedTab = sessionStorage.getItem("activeTab");
        if (savedTab) showTab(savedTab);
        const savedProxy = sessionStorage.getItem("activeProxySubTab");
        if (savedProxy) showProxySubTab(savedProxy);
        const savedUpstream = sessionStorage.getItem("activeUpstreamSubTab");
        if (savedUpstream) {
            const hideId =
                savedUpstream === "upstream-groups-view"
                    ? "upstream-list-view"
                    : "upstream-groups-view";
            const btns = document.querySelectorAll(
                "#upstreams > .sub-tabs > .tab",
            );
            const btn =
                savedUpstream === "upstream-groups-view" ? btns[1] : btns[0];
            showSubTab(savedUpstream, hideId, btn);
        }
    } catch (e) {}

    // Keep-alive ping
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

    // Fetch current user info
    api("GET", "/api/me").then((d) => {
        meData = d;
        renderMe();
    });

    // Initial load
    refresh();
    // Auto-refresh every 30s
    setInterval(refresh, 30000);
} // end else (Telegram gate)
