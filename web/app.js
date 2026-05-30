/**
 * QIP Review UI — Application Logic
 */

let patches = [];
let currentIndex = -1;

// ─── Init ────────────────────────────────────────────────────────────────────

async function init() {
    await loadStatus();
    await loadPatches();
    setupKeyboard();
}

async function loadStatus() {
    const res = await fetch('/api/status');
    const data = await res.json();
    document.getElementById('runId').textContent = data.run_id || 'unknown';
    updateStats(data);
}

async function loadPatches() {
    const res = await fetch('/api/patches');
    patches = await res.json();
    renderPatchList();
    if (patches.length > 0) {
        selectPatch(0);
    }
}

// ─── Rendering ───────────────────────────────────────────────────────────────

function renderPatchList() {
    const list = document.getElementById('patchList');
    list.innerHTML = patches.map((p, i) => `
        <div class="patch-item ${i === currentIndex ? 'active' : ''} ${p.review_status || ''}"
             onclick="selectPatch(${i})" id="patch-${i}">
            <div class="patch-item-cve">${p.cve_id || 'Unknown CVE'}</div>
            <div class="patch-item-component">${p.component || ''}${p.old_version ? '@' + p.old_version : ''}</div>
            <span class="patch-item-badge badge-${p.severity || 'medium'}">${p.severity || 'medium'}</span>
            ${p.review_status && p.review_status !== 'pending' ? 
                `<span class="patch-item-badge" style="margin-left:4px">${p.review_status}</span>` : ''}
        </div>
    `).join('');
}

function selectPatch(index) {
    if (index < 0 || index >= patches.length) return;
    currentIndex = index;
    const patch = patches[index];

    // Update sidebar active state
    renderPatchList();

    // Update header
    document.getElementById('patchTitle').textContent = 
        `${patch.cve_id}: ${patch.component || 'unknown'}`;

    // Metadata
    const meta = document.getElementById('patchMeta');
    meta.innerHTML = `
        <span>📦 ${patch.component || '?'}@${patch.old_version || '?'} → ${patch.new_version || '?'}</span>
        <span>⚡ ${(patch.cvss_score || 0).toFixed(1)} CVSS</span>
        <span>🎯 ${patch.confidence || 'medium'} confidence</span>
        <span>🔧 ${patch.fix_type || 'dep-bump'}</span>
        <span>${testIcon(patch.test_result)} tests</span>
    `;

    // Render diff
    const diffContainer = document.getElementById('diffContainer');
    if (patch.diff_content) {
        try {
            const diff2htmlUi = new Diff2HtmlUI(diffContainer, patch.diff_content, {
                drawFileList: false,
                matching: 'lines',
                outputFormat: 'side-by-side',
                highlight: true,
            });
            diff2htmlUi.draw();
        } catch (e) {
            // Fallback: show raw diff
            diffContainer.innerHTML = `<pre style="padding:16px;overflow:auto;font-size:12px">${escapeHtml(patch.diff_content)}</pre>`;
        }
    } else {
        diffContainer.innerHTML = '<p class="placeholder">No diff content available</p>';
    }

    // Show actions
    document.getElementById('patchActions').style.display = 'flex';
}

// ─── Actions ─────────────────────────────────────────────────────────────────

async function submitReview(action) {
    if (currentIndex < 0) return;
    const patch = patches[currentIndex];

    const res = await fetch('/api/review', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            patch_id: patch.patch_id,
            action: action,
        }),
    });

    if (res.ok) {
        const result = await res.json();
        patches[currentIndex].review_status = result.status;
        renderPatchList();
        await loadStatus();

        // Auto-advance to next pending
        const nextPending = patches.findIndex((p, i) => i > currentIndex && p.review_status === 'pending');
        if (nextPending >= 0) {
            selectPatch(nextPending);
        }
    }
}

// ─── Button handlers ─────────────────────────────────────────────────────────

document.getElementById('btnApprove').addEventListener('click', () => submitReview('approve'));
document.getElementById('btnReject').addEventListener('click', () => submitReview('reject'));
document.getElementById('btnSkip').addEventListener('click', () => submitReview('skip'));

// ─── Keyboard shortcuts ──────────────────────────────────────────────────────

function setupKeyboard() {
    document.addEventListener('keydown', (e) => {
        if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;

        switch (e.key) {
            case 'a': submitReview('approve'); break;
            case 'r': submitReview('reject'); break;
            case 's': submitReview('skip'); break;
            case 'j': selectPatch(currentIndex + 1); break;
            case 'k': selectPatch(currentIndex - 1); break;
            case '?':
                const help = document.getElementById('keyboardHelp');
                help.style.display = help.style.display === 'none' ? 'block' : 'none';
                break;
        }
    });
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function updateStats(data) {
    document.getElementById('statApproved').textContent = `${data.approved || 0} approved`;
    document.getElementById('statRejected').textContent = `${data.rejected || 0} rejected`;
    document.getElementById('statPending').textContent = `${data.pending || 0} pending`;
    document.getElementById('btnDeploy').disabled = (data.approved || 0) === 0;
}

function testIcon(result) {
    return { pass: '✅', fail: '❌', skip: '⚠️' }[result] || '⚠️';
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ─── Start ───────────────────────────────────────────────────────────────────

init();
