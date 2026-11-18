import os
from pathlib import Path
from webscanpro.core.reporter import SecurityReportGenerator

def test_generate_pdf_report(sample_scan):
    pdf_path = SecurityReportGenerator.generate_pdf_report(sample_scan)
    assert os.path.exists(pdf_path)
    assert pdf_path.endswith(".pdf")
    # Verify file is not empty and has PDF magic header %PDF
    with open(pdf_path, "rb") as f:
        header = f.read(5)
        assert header == b"%PDF-"

def test_view_html_report(client, sample_scan):
    resp = client.get(f"/reports/scan/{sample_scan.id}/html")
    assert resp.status_code == 200
    assert b"WebScanPro" in resp.data
    assert b"Security Assessment Report" in resp.data
    assert b"Content-Security-Policy" in resp.data
