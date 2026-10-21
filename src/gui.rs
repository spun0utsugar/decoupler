use crate::ir::DecoupledDocument;
use std::path::Path;

#[cfg(feature = "gui")]
pub fn launch_local_gui(initial_doc: Option<DecoupledDocument>, out_dir: &Path, port: u16) -> std::io::Result<()> {
    use tiny_http::{Header, Response, Server};

    let addr = format!("127.0.0.1:{}", port);
    let server = Server::http(&addr)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

    println!("================================================================================");
    println!(" OpenArchive Decoupler Local Workbench GUI listening on http://{}", addr);
    println!(" Zero external network calls | Read-only binary inspection | Press Ctrl+C to stop");
    println!("================================================================================");

    let doc_json = initial_doc
        .as_ref()
        .and_then(|d| serde_json::to_string(d).ok())
        .unwrap_or_else(|| "null".to_string());
    let out_dir_str = out_dir.display().to_string();

    for request in server.incoming_requests() {
        let url = request.url().to_string();
        if url == "/api/ir" {
            let header = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap();
            let _ = request.respond(Response::from_string(doc_json.clone()).with_header(header));
        } else {
            let html = render_workbench_html(&doc_json, &out_dir_str);
            let header = Header::from_bytes(&b"Content-Type"[..], &b"text/html; charset=utf-8"[..]).unwrap();
            let _ = request.respond(Response::from_string(html).with_header(header));
        }
    }
    Ok(())
}

#[cfg(not(feature = "gui"))]
pub fn launch_local_gui(_initial_doc: Option<DecoupledDocument>, _out_dir: &Path, _port: u16) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "GUI feature was disabled at compile time",
    ))
}

#[allow(dead_code)]
fn render_workbench_html(doc_json: &str, out_dir: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>OpenArchive Decoupler — Local Structural Workbench</title>
<style>
  :root {{ --bg: #0f172a; --panel: #1e293b; --text: #f8fafc; --muted: #94a3b8; --accent: #38bdf8; --ok: #22c55e; --warn: #f59e0b; }}
  body {{ margin: 0; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; background: var(--bg); color: var(--text); display: grid; grid-template-columns: 360px 1fr; height: 100vh; overflow: hidden; }}
  aside {{ background: var(--panel); border-right: 1px solid #334155; padding: 16px; overflow-y: auto; }}
  main {{ display: flex; flex-direction: column; padding: 16px; overflow-y: auto; gap: 16px; }}
  h1 {{ font-size: 16px; margin: 0 0 8px 0; color: var(--accent); }}
  .card {{ background: #0f172a; border: 1px solid #334155; border-radius: 6px; padding: 12px; margin-bottom: 12px; font-size: 12px; }}
  .badge {{ display: inline-block; padding: 2px 6px; border-radius: 4px; background: #0284c7; color: white; font-size: 11px; }}
  #canvas-wrap {{ flex: 1; background: #020617; border: 1px solid #334155; border-radius: 6px; display: flex; align-items: center; justify-content: center; min-height: 420px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 12px; }}
  th, td {{ text-align: left; padding: 6px 8px; border-bottom: 1px solid #334155; }}
</style>
</head>
<body>
<aside>
  <h1>OpenArchive Decoupler</h1>
  <div class="card" id="meta-box">Loading IR...</div>
  <div class="card">
    <strong>Export Output Directory:</strong><br/>
    <span style="color:var(--muted)">{out_dir}</span>
  </div>
  <div class="card" id="layers-box"></div>
</aside>
<main>
  <div id="canvas-wrap"><div id="svg-target">No document loaded</div></div>
  <div class="card">
    <strong>Provenance &amp; Confidence Audit Table</strong>
    <table id="prov-table">
      <thead><tr><th>Entity ID</th><th>Type</th><th>Byte Offset</th><th>Length</th><th>Detector</th><th>Confidence</th></tr></thead>
      <tbody></tbody>
    </table>
  </div>
</main>
<script>
const DOC = {doc_json};
if (DOC) {{
  document.getElementById('meta-box').innerHTML = `
    <div><strong>File:</strong> ${{DOC.metadata.source_filename}}</div>
    <div><strong>Size:</strong> ${{DOC.metadata.file_size}} B</div>
    <div><strong>SHA-256:</strong> ${{DOC.metadata.sha256.slice(0,16)}}...</div>
    <div><strong>Magic:</strong> ${{DOC.metadata.detected_magic}}</div>
    <div><strong>Entropy:</strong> ${{DOC.metadata.overall_entropy}} bits/B</div>
  `;
  const tbody = document.querySelector('#prov-table tbody');
  DOC.layers.forEach(l => {{
    l.features.forEach(f => {{
      const tr = document.createElement('tr');
      tr.innerHTML = `<td>${{f.id}}</td><td>${{f.geometry.type}}</td><td>0x${{f.provenance.span.offset.toString(16)}}</td><td>${{f.provenance.span.length}} B</td><td>${{f.provenance.detector}}</td><td><span class="badge">${{f.provenance.confidence.composite}}</span></td>`;
      tbody.appendChild(tr);
    }});
  }});
}}
</script>
</body>
</html>"#,
        out_dir = out_dir,
        doc_json = doc_json
    )
}
