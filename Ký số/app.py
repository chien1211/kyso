from flask import Flask, request, send_file, jsonify, render_template_string, redirect, url_for
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import os
import uuid
import base64

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Tạo/cập nhật khóa RSA
KEY_FILE = "private.pem"
if not os.path.exists(KEY_FILE):
    key = RSA.generate(2048)
    with open("private.pem", "wb") as f:
        f.write(key.export_key())
    with open("public.pem", "wb") as f:
        f.write(key.publickey().export_key())
else:
    key = RSA.import_key(open("private.pem").read())
public_key = key.publickey()

files_db = {}

# Giao diện gửi file
HTML_CONTENT = """
<!DOCTYPE html>
<html lang="vi">
<head>
  <meta charset="UTF-8" />
  <title>Gửi File Ký Số RSA</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet" />
</head>
<body class="bg-light">
<div class="container py-4">
  <h2 class="text-center mb-4">📤 Gửi File Kèm Chữ Ký Số</h2>
  <form id="sendForm">
    <div class="mb-3">
      <label class="form-label">Chọn file:</label>
      <input type="file" class="form-control" id="sendFile" required>
    </div>
    <button type="submit" class="btn btn-primary">Gửi File</button>
    <a href="/receive" class="btn btn-link float-end">🔽 Đến trang Nhận</a>
  </form>
  <div id="sendStatus" class="mt-4"></div>
</div>

<script>
const sendForm = document.getElementById('sendForm');
const sendStatus = document.getElementById('sendStatus');

sendForm.addEventListener('submit', async e => {
  e.preventDefault();
  const fileInput = document.getElementById('sendFile');
  if (fileInput.files.length === 0) return alert("Vui lòng chọn file.");

  const file = fileInput.files[0];
  const formData = new FormData();
  formData.append("file", file);

  sendStatus.innerHTML = "⏳ Đang gửi file...";

  const resp = await fetch('/api/upload', { method: 'POST', body: formData });
  const data = await resp.json();

  if (resp.ok) {
    sendStatus.innerHTML = `
      <div class="alert alert-success">
        ✅ Gửi file thành công!<br>
        <strong>File ID:</strong> ${data.file_id}<br>
        <strong>Chữ ký (Base64):</strong>
        <textarea class="form-control mt-2" rows="3" readonly>${data.signature}</textarea>
        <button class="btn btn-sm btn-outline-primary mt-2" onclick="navigator.clipboard.writeText('${data.signature}')">📋 Sao chép chữ ký</button>
        <hr>
        🔐 <strong>Khóa công khai:</strong>
        <button class="btn btn-sm btn-outline-secondary" onclick="getPublicKey()">Xem khóa công khai</button>
        <pre id="pubkeyBox" class="bg-light border rounded p-2 mt-2 text-wrap" style="display:none;"></pre>
      </div>
    `;
  } else {
    sendStatus.innerHTML = `<div class="alert alert-danger">❌ Lỗi khi gửi file!</div>`;
  }
});

async function getPublicKey() {
  const resp = await fetch('/public_key');
  if (resp.ok) {
    const pubkey = await resp.text();
    const box = document.getElementById('pubkeyBox');
    box.style.display = 'block';
    box.textContent = pubkey;
  }
}
</script>
</body>
</html>
"""

# Giao diện nhận & xác minh
RECEIVE_HTML = """
<!DOCTYPE html>
<html lang="vi">
<head>
  <meta charset="UTF-8">
  <title>Nhận và Xác Minh File</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
<div class="container py-4">
  <h2 class="text-center mb-4">📥 Nhận và Xác Minh File</h2>
  <div id="fileList" class="mt-3"></div>
  <a href="/send" class="btn btn-link">⬅️ Quay lại trang Gửi</a>
</div>

<script>
async function loadFiles() {
  const res = await fetch("/api/files");
  const files = await res.json();

  const container = document.getElementById("fileList");
  if (files.length === 0) {
    container.innerHTML = "<div class='alert alert-warning'>Chưa có file nào.</div>";
    return;
  }

  let html = '<ul class="list-group">';
  for (const file of files) {
    html += `
      <li class="list-group-item d-flex justify-content-between align-items-center">
        📄 ${file.filename}
        <div>
          <a class="btn btn-sm btn-success" href="/download/${file.file_id}">⬇️ Tải</a>
          <button class="btn btn-sm btn-outline-primary" onclick="verifyFile('${file.file_id}')">✔️ Xác minh</button>
        </div>
      </li>
      <div id="verify-${file.file_id}" class="mt-1 ms-3 text-muted"></div>
    `;
  }
  html += '</ul>';
  container.innerHTML = html;
}

async function verifyFile(file_id) {
  const res = await fetch(`/api/verify/${file_id}`);
  const result = await res.json();
  const box = document.getElementById(`verify-${file_id}`);
  if (result.valid) {
    box.innerHTML = "<span class='text-success'>✅ Chữ ký hợp lệ</span>";
  } else {
    box.innerHTML = "<span class='text-danger'>❌ Chữ ký không hợp lệ</span>";
  }
}

loadFiles();
</script>
</body>
</html>
"""

# --- Các route ---
@app.route("/")
def home():
    return redirect(url_for("send"))

@app.route("/send")
def send():
    return render_template_string(HTML_CONTENT)

@app.route("/receive")
def receive():
    return render_template_string(RECEIVE_HTML)

@app.route("/api/upload", methods=["POST"])
def upload():
    file = request.files.get("file")
    if not file:
        return jsonify({"error": "No file"}), 400

    data = file.read()
    hash_obj = SHA256.new(data)
    signature = pkcs1_15.new(key).sign(hash_obj)
    signature_b64 = base64.b64encode(signature).decode()

    file_id = str(uuid.uuid4())
    filename = file.filename
    file_path = os.path.join(UPLOAD_FOLDER, f"{file_id}_{filename}")
    sig_path = os.path.join(UPLOAD_FOLDER, f"{file_id}.sig")

    with open(file_path, "wb") as f:
        f.write(data)
    with open(sig_path, "wb") as f:
        f.write(signature)

    files_db[file_id] = {
        "filename": filename,
        "filepath": file_path,
        "sigpath": sig_path,
        "timestamp": os.path.getmtime(file_path)
    }

    return jsonify({"file_id": file_id, "signature": signature_b64})

@app.route("/api/files")
def list_files():
    return jsonify([
        {"file_id": fid, "filename": info["filename"], "timestamp": info["timestamp"]}
        for fid, info in files_db.items()
    ])

@app.route("/download/<file_id>")
def download(file_id):
    info = files_db.get(file_id)
    if not info:
        return "File not found", 404
    return send_file(info["filepath"], as_attachment=True, download_name=info["filename"])

@app.route("/api/verify/<file_id>")
def verify(file_id):
    info = files_db.get(file_id)
    if not info:
        return jsonify({"valid": False}), 404

    with open(info["filepath"], "rb") as f:
        data = f.read()
    with open(info["sigpath"], "rb") as f:
        signature = f.read()

    h = SHA256.new(data)
    try:
        pkcs1_15.new(public_key).verify(h, signature)
        return jsonify({"valid": True})
    except (ValueError, TypeError):
        return jsonify({"valid": False})

@app.route("/public_key")
def get_public_key():
    return public_key.export_key().decode()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
