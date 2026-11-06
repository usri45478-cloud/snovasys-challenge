import os
import sqlite3
from datetime import datetime
from fastapi import FastAPI, Request, Form, UploadFile, File, HTTPException, status
from fastapi.responses import HTMLResponse, FileResponse, RedirectResponse

app = FastAPI(title="TrustVault")

UPLOAD_DIR = "secure_vault"
os.makedirs(UPLOAD_DIR, exist_ok=True)

def get_db():
    conn = sqlite3.connect("trustvault.db")
    conn.row_factory = sqlite3.Row
    return conn

def log_audit(username: str, action: str, resource_id: str, status_val: str, details: str = ""):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO audit_logs (timestamp, username, action, resource_id, status, details) VALUES (?, ?, ?, ?, ?, ?)",
        (datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"), username, action, str(resource_id), status_val, details)
    )
    conn.commit()
    conn.close()

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>TrustVault - Secure Sharing & Audit</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-900 text-slate-100 min-h-screen p-6 font-sans">
    <div class="max-w-6xl mx-auto space-y-6">
        <header class="flex justify-between items-center border-b border-slate-700 pb-4">
            <div>
                <h1 class="text-3xl font-bold tracking-tight text-indigo-400">TrustVault</h1>
                <p class="text-sm text-slate-400">Strict Authorization & Tamper-Evident Audit Trail</p>
            </div>
            <div class="text-right">
                <span class="inline-block bg-indigo-950 border border-indigo-700 px-3 py-1 rounded text-sm">
                    Current User: <strong class="text-indigo-300">{{ current_user }}</strong> ({{ current_role }})
                </span>
            </div>
        </header>

        <form method="get" action="/" class="flex gap-2">
            <input type="text" name="q" value="{{ query }}" placeholder="Search documents..." class="flex-1 bg-slate-800 border border-slate-700 px-4 py-2 rounded text-sm text-slate-200">
            <button type="submit" class="bg-indigo-600 hover:bg-indigo-500 px-5 py-2 rounded text-sm font-semibold">Search</button>
        </form>

        <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div class="bg-slate-800 border border-slate-700 rounded-lg p-5">
                <h2 class="text-lg font-semibold text-slate-200 mb-4">Upload Document</h2>
                <form action="/upload" method="post" enctype="multipart/form-data" class="space-y-4">
                    <input type="hidden" name="user" value="{{ current_user }}">
                    <div>
                        <label class="block text-xs text-slate-400 mb-1">Select File</label>
                        <input type="file" name="file" required class="w-full text-xs text-slate-300 file:mr-3 file:py-1.5 file:px-3 file:rounded file:border-0 file:text-xs file:bg-slate-700 file:text-slate-200">
                    </div>
                    <div>
                        <label class="block text-xs text-slate-400 mb-1">Category</label>
                        <input type="text" name="category" placeholder="Confidential, HR..." class="w-full bg-slate-900 border border-slate-700 px-3 py-1.5 rounded text-sm">
                    </div>
                    <button type="submit" class="w-full bg-indigo-600 hover:bg-indigo-500 py-2 rounded text-sm font-medium">Securely Upload</button>
                </form>
            </div>

            <div class="md:col-span-2 bg-slate-800 border border-slate-700 rounded-lg p-5">
                <h2 class="text-lg font-semibold text-slate-200 mb-4">Accessible Documents</h2>
                <table class="w-full text-left text-sm">
                    <thead class="text-xs text-slate-400 uppercase border-b border-slate-700">
                        <tr>
                            <th class="py-2">ID</th>
                            <th class="py-2">Filename</th>
                            <th class="py-2">Owner</th>
                            <th class="py-2">Category</th>
                            <th class="py-2 text-right">Actions</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-slate-700 text-slate-300">
                        {% for doc in docs %}
                        <tr>
                            <td class="py-2 text-slate-500">#{{ doc.id }}</td>
                            <td class="py-2 font-medium text-slate-100">{{ doc.filename }}</td>
                            <td class="py-2">{{ doc.owner }}</td>
                            <td class="py-2"><span class="bg-slate-700 px-2 py-0.5 rounded text-xs">{{ doc.category }}</span></td>
                            <td class="py-2 text-right">
                                <a href="/download/{{ doc.id }}?user={{ current_user }}" class="text-indigo-400 hover:underline text-xs">Download</a>
                            </td>
                        </tr>
                        {% else %}
                        <tr>
                            <td colspan="5" class="py-4 text-center text-slate-500 text-xs">No documents found.</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>

        <div class="bg-slate-800 border border-slate-700 rounded-lg p-5">
            <h2 class="text-lg font-semibold text-slate-200 mb-3">Share Access</h2>
            <form action="/grant" method="post" class="grid grid-cols-1 md:grid-cols-4 gap-3">
                <input type="hidden" name="current_user" value="{{ current_user }}">
                <input type="number" name="doc_id" placeholder="Doc ID" required class="bg-slate-900 border border-slate-700 px-3 py-1.5 rounded text-sm">
                <input type="text" name="target_user" placeholder="Recipient (e.g. bob)" required class="bg-slate-900 border border-slate-700 px-3 py-1.5 rounded text-sm">
                <select name="permission" class="bg-slate-900 border border-slate-700 px-3 py-1.5 rounded text-sm">
                    <option value="download">Download</option>
                    <option value="read">Read</option>
                </select>
                <button type="submit" class="bg-emerald-600 hover:bg-emerald-500 py-1.5 rounded text-sm font-medium">Grant Access</button>
            </form>
        </div>

        <div class="bg-slate-800 border border-slate-700 rounded-lg p-5">
            <h2 class="text-lg font-semibold text-slate-200 mb-3">Audit Trail</h2>
            <div class="overflow-x-auto max-h-56">
                <table class="w-full text-left text-xs font-mono">
                    <thead class="text-slate-400 uppercase border-b border-slate-700">
                        <tr>
                            <th class="py-2">Time (UTC)</th>
                            <th class="py-2">User</th>
                            <th class="py-2">Action</th>
                            <th class="py-2">Doc ID</th>
                            <th class="py-2">Status</th>
                            <th class="py-2">Details</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-slate-700">
                        {% for log in logs %}
                        <tr>
                            <td class="py-1.5 text-slate-400">{{ log.timestamp }}</td>
                            <td class="py-1.5 text-slate-200">{{ log.username }}</td>
                            <td class="py-1.5">{{ log.action }}</td>
                            <td class="py-1.5">#{{ log.resource_id or '-' }}</td>
                            <td class="py-1.5">
                                {% if log.status == 'ALLOWED' %}
                                <span class="text-emerald-400 font-bold">ALLOWED</span>
                                {% else %}
                                <span class="text-rose-400 font-bold">DENIED</span>
                                {% endif %}
                            </td>
                            <td class="py-1.5 text-slate-400">{{ log.details }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
def index(request: Request, user: str = "alice", q: str = ""):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT role FROM users WHERE username = ?", (user,))
    row = cursor.fetchone()
    role = row["role"] if row else "USER"
    
    if role == "ADMIN":
        cursor.execute("SELECT * FROM documents ORDER BY id DESC")
    else:
        cursor.execute("""
        SELECT DISTINCT d.* FROM documents d
        LEFT JOIN permissions p ON d.id = p.doc_id
        WHERE (d.owner = ? OR p.username = ?)
        ORDER BY d.id DESC
        """, (user, user))
    docs = cursor.fetchall()

    if role == "ADMIN":
        cursor.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 50")
    else:
        cursor.execute("SELECT * FROM audit_logs WHERE username = ? ORDER BY id DESC LIMIT 50", (user,))
    logs = cursor.fetchall()
    conn.close()

    from jinja2 import Template
    t = Template(HTML_TEMPLATE)
    return t.render(current_user=user, current_role=role, docs=docs, logs=logs, query=q)

@app.post("/upload")
async def upload_file(user: str = Form(...), category: str = Form("General"), file: UploadFile = File(...)):
    filename = os.path.basename(file.filename)
    stored_name = f"{int(datetime.utcnow().timestamp())}_{filename}"
    file_path = os.path.abspath(os.path.join(UPLOAD_DIR, stored_name))
    
    content = await file.read()
    with open(file_path, "wb") as f:
        f.write(content)
        
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO documents (filename, file_path, owner, category, created_at) VALUES (?, ?, ?, ?, ?)",
        (filename, file_path, user, category, datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))
    )
    doc_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    log_audit(user, "UPLOAD", str(doc_id), "ALLOWED", f"Uploaded {filename}")
    return RedirectResponse(f"/?user={user}", status_code=status.HTTP_303_SEE_OTHER)

@app.get("/download/{doc_id}")
def download_file(doc_id: int, user: str = "alice"):
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("SELECT role FROM users WHERE username = ?", (user,))
    u_row = cursor.fetchone()
    role = u_row["role"] if u_row else "USER"
    
    cursor.execute("SELECT * FROM documents WHERE id = ?", (doc_id,))
    doc = cursor.fetchone()
    
    if not doc:
        log_audit(user, "DOWNLOAD", str(doc_id), "DENIED", "Document not found")
        conn.close()
        raise HTTPException(status_code=404, detail="Document not found")
        
    cursor.execute("SELECT * FROM permissions WHERE doc_id = ? AND username = ?", (doc_id, user))
    perm = cursor.fetchone()
    
    is_owner = (doc["owner"] == user)
    is_admin = (role == "ADMIN")
    has_perm = (perm is not None)
    
    if not (is_owner or is_admin or has_perm):
        log_audit(user, "DOWNLOAD", str(doc_id), "DENIED", f"User {user} unauthorized")
        conn.close()
        raise HTTPException(status_code=403, detail="Forbidden: You do not have permission")
        
    file_path = os.path.abspath(doc["file_path"])
    if not os.path.exists(file_path):
        log_audit(user, "DOWNLOAD", str(doc_id), "DENIED", "File missing on disk")
        conn.close()
        raise HTTPException(status_code=404, detail="File missing on disk")

    log_audit(user, "DOWNLOAD", str(doc_id), "ALLOWED", f"User {user} downloaded document")
    conn.close()
    
    return FileResponse(path=file_path, filename=doc["filename"])

@app.post("/grant")
def grant_access(current_user: str = Form(...), doc_id: int = Form(...), target_user: str = Form(...), permission: str = Form("download")):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT owner FROM documents WHERE id = ?", (doc_id,))
    doc = cursor.fetchone()
    
    if not doc:
        conn.close()
        raise HTTPException(status_code=404, detail="Document not found")
        
    cursor.execute("SELECT role FROM users WHERE username = ?", (current_user,))
    role = cursor.fetchone()["role"]
    
    if doc["owner"] != current_user and role != "ADMIN":
        log_audit(current_user, "GRANT_PERMISSION", str(doc_id), "DENIED", "Unauthorized grant")
        conn.close()
        raise HTTPException(status_code=403, detail="Only owner or admin can share")
        
    cursor.execute("INSERT INTO permissions (doc_id, username, permission) VALUES (?, ?, ?)", (doc_id, target_user, permission))
    conn.commit()
    conn.close()
    
    log_audit(current_user, "GRANT_PERMISSION", str(doc_id), "ALLOWED", f"Granted to {target_user}")
    return RedirectResponse(f"/?user={current_user}", status_code=status.HTTP_303_SEE_OTHER)