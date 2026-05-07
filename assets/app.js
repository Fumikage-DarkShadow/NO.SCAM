(() => {
    'use strict';

    const DATA_DIR = 'data';
    const BATCH_SIZE = 100;

    // ---------- State ----------
    const state = {
        meta: null,
        // One Set per source. Looked up in priority order so the user sees the
        // most informative source first (ABE = official French list).
        bySource: {
            'ABE Info Service':   { set: new Set(), defaultCat: 'Liste noire AMF/ACPR' },
            'URLhaus (abuse.ch)': { set: new Set(), defaultCat: 'Malware' },
            'OpenPhish':          { set: new Set(), defaultCat: 'Phishing' },
            'Phishing.Database':  { set: new Set(), defaultCat: 'Phishing' },
        },
        // Rich detail (ABE-only — the small set with categories worth showing)
        abeDetail: new Map(),
    };

    // ---------- Utilities ----------
    function $(sel) { return document.querySelector(sel); }
    function $$(sel) { return document.querySelectorAll(sel); }

    function fmtNum(n) {
        return new Intl.NumberFormat('fr-FR').format(n);
    }

    function fmtDate(iso) {
        try {
            return new Date(iso).toLocaleString('fr-FR', {
                day: 'numeric', month: 'long', year: 'numeric',
                hour: '2-digit', minute: '2-digit',
            });
        } catch { return iso; }
    }

    function escapeHtml(s) {
        return String(s).replace(/[&<>"']/g, c => ({
            '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
        }[c]));
    }

    function highlight(text, query) {
        if (!query) return escapeHtml(text);
        const safe = escapeHtml(text);
        const safeQ = escapeHtml(query).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        return safe.replace(new RegExp(safeQ, 'gi'), m => `<mark>${m}</mark>`);
    }

    function normalizeInput(raw) {
        let v = raw.trim().toLowerCase();
        if (!v) return null;
        if (v.includes('@')) return { type: 'email', value: v };
        v = v.replace(/^https?:\/\//, '').replace(/^www\./, '').replace(/[/.]+$/, '');
        v = v.split('/')[0];
        return { type: 'url', value: v };
    }

    // ---------- Data loading ----------
    function setLoadingMessage(msg) {
        const el = document.querySelector('#loading p');
        if (el) el.textContent = msg;
    }

    function yieldToBrowser() {
        return new Promise(resolve => setTimeout(resolve, 0));
    }

    async function parseLookupInChunks(text) {
        const lines = text.split('\n');
        const total = lines.length;
        const CHUNK = 50000;

        // Pre-resolve source bucket for first match speed
        const buckets = state.bySource;

        for (let i = 0; i < total; i += CHUNK) {
            const end = Math.min(i + CHUNK, total);
            for (let j = i; j < end; j++) {
                const line = lines[j];
                if (!line) continue;
                const idx1 = line.indexOf('|');
                if (idx1 < 0) continue;
                const idx2 = line.indexOf('|', idx1 + 1);
                if (idx2 < 0) continue;
                const idx3 = line.indexOf('|', idx2 + 1);
                if (idx3 < 0) continue;

                const value = line.slice(idx1 + 1, idx2);
                const source = line.slice(idx2 + 1, idx3);
                // For the official French list we keep the category; for the
                // bulk anti-phishing/malware sources the default category is
                // good enough — saves ~100 MB of memory at 400k entries.
                const bucket = buckets[source];
                if (bucket) {
                    bucket.set.add(value);
                    if (source === 'ABE Info Service') {
                        const category = line.slice(idx3 + 1);
                        const t = line.charCodeAt(0) === 101 ? 'email' : 'url';
                        state.abeDetail.set(value, { type: t, category });
                    }
                }
            }
            const pct = Math.round((end / total) * 100);
            setLoadingMessage(`Indexation des entrées… ${pct}%`);
            await yieldToBrowser();
        }
    }

    async function loadData() {
        setLoadingMessage('Téléchargement de la base (≈ 25 Mo)…');
        const [metaRes, txtRes] = await Promise.all([
            fetch(`${DATA_DIR}/meta.json`),
            fetch(`${DATA_DIR}/blacklist.txt`),
        ]);

        if (!metaRes.ok || !txtRes.ok) {
            throw new Error(`Erreur de chargement des données (${metaRes.status}/${txtRes.status})`);
        }

        state.meta = await metaRes.json();
        const text = await txtRes.text();

        await parseLookupInChunks(text);
    }

    // ---------- UI bindings ----------
    function renderStats() {
        const m = state.meta;
        const total = m.total;
        const urls = m.stats.by_type.url || 0;
        const emails = m.stats.by_type.email || 0;
        const sources = Object.keys(m.stats.by_source || {}).length;

        const setAll = (key, value) => {
            $$(`[data-stat="${key}"]`).forEach(el => { el.textContent = fmtNum(value); });
        };
        setAll('total', total);
        setAll('urls', urls);
        setAll('emails', emails);
        setAll('sources', sources);
        $('#updated-at').textContent = fmtDate(m.generated_at);
    }

    function renderSources() {
        const container = $('#sources-cards');
        const counts = state.meta.stats.by_source || {};
        const html = state.meta.sources.map(s => `
            <article class="card">
                <h3>${escapeHtml(s.name)}</h3>
                <div class="card__count">${fmtNum(counts[s.name] || 0)} entrées</div>
                <p>${escapeHtml(s.description)}</p>
                <a href="${escapeHtml(s.url)}" target="_blank" rel="noopener">Voir la source &rarr;</a>
            </article>
        `).join('');
        container.innerHTML = html;
    }


    // ---------- Check feature ----------
    function findInSources(value) {
        // Priority order: official French list first, then phishing, then malware.
        const order = ['ABE Info Service', 'OpenPhish', 'Phishing.Database', 'URLhaus (abuse.ch)'];
        const hits = [];
        for (const source of order) {
            if (state.bySource[source].set.has(value)) {
                const detail = state.abeDetail.get(value);
                hits.push({
                    source,
                    type: detail?.type || (value.includes('@') ? 'email' : 'url'),
                    category: detail?.category || state.bySource[source].defaultCat,
                });
            }
        }
        return hits;
    }

    function check(rawInput) {
        const result = $('#result');
        const parsed = normalizeInput(rawInput);
        if (!parsed) {
            result.hidden = false;
            result.className = 'result result--warning';
            result.innerHTML = `<div class="result__title">⚠️ Saisie vide</div><div class="result__detail">Entrez une URL ou un e-mail.</div>`;
            return;
        }

        let hits = findInSources(parsed.value);
        let matchedAs = null;

        // For URLs, also try without subdomain (mail.example.com -> example.com)
        if (hits.length === 0 && parsed.type === 'url') {
            const parts = parsed.value.split('.');
            for (let i = 1; i < parts.length - 1; i++) {
                const candidate = parts.slice(i).join('.');
                hits = findInSources(candidate);
                if (hits.length) { matchedAs = candidate; break; }
            }
        }

        result.hidden = false;
        if (hits.length) {
            const matched = matchedAs
                ? ` (correspondance sur le domaine racine <code>${escapeHtml(matchedAs)}</code>)`
                : '';
            const chips = hits.map(h => `
                <span class="result__chip">Source · ${escapeHtml(h.source)}</span>
                <span class="result__chip">Catégorie · ${escapeHtml(h.category)}</span>`).join(' ');
            result.className = 'result result--danger';
            result.innerHTML = `
                <div class="result__title">🚨 Présent dans la liste noire</div>
                <div class="result__detail">
                    <strong>${escapeHtml(parsed.value)}</strong> figure dans la base${matched}.<br>
                    ${chips}
                </div>`;
        } else {
            result.className = 'result result--success';
            result.innerHTML = `
                <div class="result__title">✅ Absent des listes noires consultées</div>
                <div class="result__detail">
                    <strong>${escapeHtml(parsed.value)}</strong> n'a pas été trouvé.<br>
                    <em>Attention :</em> cela ne garantit pas qu'il s'agisse d'un site fiable. Restez prudent et vérifiez d'autres signaux (HTTPS, mentions légales, avis utilisateurs).
                </div>`;
        }
    }

    // ---------- Init ----------
    async function init() {
        try {
            await loadData();
        } catch (err) {
            console.error(err);
            $('#loading').innerHTML = `
                <div style="max-width:520px;text-align:center;padding:24px">
                    <div style="font-size:32px">⚠️</div>
                    <p style="color:#fecaca;margin-top:12px">${escapeHtml(err.message)}</p>
                    <p style="margin-top:12px;font-size:13px">Si vous testez en local, lancez un petit serveur HTTP (les <code>fetch()</code> ne marchent pas avec <code>file://</code>) :<br>
                    <code style="display:inline-block;margin-top:8px;padding:6px 10px;background:#1a2235;border-radius:6px">python -m http.server 8000</code></p>
                </div>`;
            return;
        }

        renderStats();
        renderSources();
        $('#loading').hidden = true;

        // Search/check bindings — only on click or Enter
        $('#check-btn').addEventListener('click', () => check($('#search-input').value));
        $('#search-input').addEventListener('keydown', ev => {
            if (ev.key === 'Enter') check(ev.target.value);
        });

        // Hide previous result when the user edits the input
        $('#search-input').addEventListener('input', () => {
            $('#result').hidden = true;
        });
    }

    document.addEventListener('DOMContentLoaded', init);
})();
