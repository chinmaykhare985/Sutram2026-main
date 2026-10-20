let evidenceData = [];

// 1. Fetch & Load Records
async function fetchEvidence() {
  try {
    const res = await fetch('/evidence_list');
    evidenceData = await res.json();
    renderTable(evidenceData);
  } catch (err) {
    console.error('Failed to load records:', err);
  }
}

// 2. Render Records Table
function renderTable(items) {
  const tbody = document.getElementById('evidenceTableBody');
  if (!items || items.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" class="text-center py-8 text-slate-500">No evidence items logged yet.</td></tr>`;
    return;
  }

  tbody.innerHTML = items.map(item => `
    <tr class="hover:bg-slate-800/50 transition">
      <td class="py-3 px-3 font-semibold text-slate-300">#${item.artifact_id}</td>
      <td class="py-3 px-3">
        <span class="inline-block px-2 py-0.5 rounded text-[11px] font-medium bg-indigo-950 text-indigo-300 border border-indigo-800/60">
          ${escapeHtml(item.case_id)}
        </span>
      </td>
      <td class="py-3 px-3">
        <a href="/evidence_list/${item.artifact_id}/download" 
           class="font-medium text-indigo-400 hover:text-indigo-300 hover:underline inline-flex items-center gap-1.5"
           title="Click to download original file">
          <i class="fa-solid fa-download text-[11px]"></i>
          ${escapeHtml(item.original_filename)}
        </a>
        <div class="text-[11px] text-slate-500">${formatBytes(item.size_bytes)}</div>
      </td>
      <td class="py-3 px-3 text-slate-300 text-xs max-w-xs">
        ${item.remarks ? `<span class="italic text-slate-300">${escapeHtml(item.remarks)}</span>` : `<span class="text-slate-600">—</span>`}
      </td>
      <td class="py-3 px-3 hash-cell text-slate-400 text-[11px] max-w-[150px] truncate" title="${item.sha256}">
        ${item.sha256.slice(0, 10)}...${item.sha256.slice(-8)}
      </td>
      <td class="py-3 px-3 text-slate-400 text-[11px]">
        ${new Date(item.added_at_utc).toLocaleString()}
      </td>
      <td class="py-3 px-3 text-center whitespace-nowrap space-x-1" id="verify-col-${item.artifact_id}">
        <button onclick="verifyArtifact(${item.artifact_id})" 
                class="px-2 py-1 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded text-[11px] border border-slate-600 transition"
                title="Verify SHA-256 hash integrity">
          <i class="fa-solid fa-shield"></i>
        </button>
        <button onclick="analyzeArtifactWithGemini(${item.artifact_id}, '${escapeHtml(item.original_filename)}')" 
                class="px-2 py-1 bg-indigo-950 hover:bg-indigo-900 text-indigo-300 rounded text-[11px] border border-indigo-800 transition"
                title="Analyze threat indicators with Google Gemini AI">
          <i class="fa-solid fa-wand-magic-sparkles"></i> AI
        </button>
      </td>
    </tr>
  `).join('');
}

// 3. Verify Artifact Integrity
async function verifyArtifact(id) {
  const col = document.getElementById(`verify-col-${id}`);
  col.innerHTML = `<span class="text-slate-400 text-[11px]"><i class="fa-solid fa-spinner fa-spin"></i> Checking...</span>`;

  try {
    const res = await fetch(`/evidence_list/${id}/verify`);
    const data = await res.json();

    if (data.status === 'intact') {
      col.innerHTML = `<span class="inline-flex items-center gap-1 px-2 py-0.5 bg-emerald-950 text-emerald-300 border border-emerald-800 text-[11px] rounded font-medium"><i class="fa-solid fa-circle-check"></i> Intact</span>`;
    } else if (data.status === 'MODIFIED') {
      col.innerHTML = `<span class="inline-flex items-center gap-1 px-2 py-0.5 bg-rose-950 text-rose-300 border border-rose-800 text-[11px] rounded font-medium"><i class="fa-solid fa-triangle-exclamation"></i> Tampered</span>`;
    } else {
      col.innerHTML = `<span class="inline-flex items-center gap-1 px-2 py-0.5 bg-amber-950 text-amber-300 border border-amber-800 text-[11px] rounded font-medium"><i class="fa-solid fa-file-circle-xmark"></i> Missing</span>`;
    }
  } catch (err) {
    col.innerHTML = `<span class="text-rose-400 text-[11px]">Error</span>`;
  }
}

// 3b. Gemini AI Analysis Modal Handler
async function analyzeArtifactWithGemini(id, filename) {
  const modal = document.getElementById('aiModal');
  const modalTitle = document.getElementById('modalArtifactTitle');
  const modalContent = document.getElementById('modalAiContent');

  modalTitle.textContent = `#${id} - ${filename}`;
  modalContent.innerHTML = `<div class="flex items-center gap-2 text-indigo-300"><i class="fa-solid fa-circle-notch fa-spin"></i> Sending artifact to Google Gemini AI for threat analysis...</div>`;
  modal.classList.remove('hidden');

  try {
    const res = await fetch(`/evidence_list/${id}/analyze`, { method: 'POST' });
    const data = await res.json();

    if (!res.ok) {
      modalContent.innerHTML = `<div class="text-rose-400 font-semibold mb-2"><i class="fa-solid fa-triangle-exclamation"></i> Analysis Error (HTTP ${res.status}):</div><div>${escapeHtml(data.detail || 'Failed to analyze artifact.')}</div><div class="mt-4 text-slate-400 text-[11px]">Tip: Ensure the <code>GEMINI_API_KEY</code> environment variable is set on the server.</div>`;
      return;
    }

    modalContent.textContent = data.analysis;
  } catch (err) {
    modalContent.innerHTML = `<div class="text-rose-400 font-semibold"><i class="fa-solid fa-triangle-exclamation"></i> Network error connecting to analysis endpoint: ${escapeHtml(err.message)}</div>`;
  }
}

function closeAiModal() {
  document.getElementById('aiModal').classList.add('hidden');
}

// 4. Client Search Filter
function filterTable() {
  const q = document.getElementById('searchBox').value.toLowerCase();
  const filtered = evidenceData.filter(d => 
    d.case_id.toLowerCase().includes(q) || 
    d.original_filename.toLowerCase().includes(q) || 
    d.sha256.toLowerCase().includes(q)
  );
  renderTable(filtered);
}

// 5. Form Submission (Upload)
document.getElementById('uploadForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const status = document.getElementById('statusMessage');
  const submitBtn = document.getElementById('submitBtn');

  const caseId = document.getElementById('case_id').value;
  const fileInput = document.getElementById('evidenceFile');
  const remarks = document.getElementById('remarks').value;

  if (!fileInput.files.length) return;

  const formData = new FormData();
  formData.append('case_id', caseId);
  formData.append('file', fileInput.files[0]);
  if (remarks) formData.append('Remarks', remarks);

  submitBtn.disabled = true;
  submitBtn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Hashing & Uploading...`;

  try {
    const res = await fetch('/evidence_list', {
      method: 'POST',
      body: formData
    });

    const data = await res.json();

    if (res.ok) {
      status.className = "mt-4 text-xs p-3 rounded-lg bg-emerald-950 border border-emerald-800 text-emerald-300 block";
      status.innerHTML = `<strong>Success!</strong> Artifact logged with ID #${data.artifact_id}`;
      document.getElementById('uploadForm').reset();
      fetchEvidence();
    } else {
      status.className = "mt-4 text-xs p-3 rounded-lg bg-rose-950 border border-rose-800 text-rose-300 block";
      status.innerHTML = `<strong>Failed:</strong> ${data.detail || 'Could not log file'}`;
    }
  } catch (err) {
    status.className = "mt-4 text-xs p-3 rounded-lg bg-rose-950 border border-rose-800 text-rose-300 block";
    status.innerHTML = `<strong>Error:</strong> Network or server error.`;
  } finally {
    submitBtn.disabled = false;
    submitBtn.innerHTML = `<i class="fa-solid fa-shield-halved"></i> Hash & Store Evidence`;
  }
});

// Helper utilities
function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// Initial fetch
fetchEvidence();