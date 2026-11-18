from unittest.mock import patch, MagicMock
from webscanpro.core.engine import ScanEngine
from webscanpro.core.crawler import CrawledResource
from webscanpro.modules.base import FindingData
from webscanpro.models.scan import Scan

def test_engine_run_scan_thread(app, sample_target):
    with app.app_context():
        scan = Scan(
            target_id=sample_target.id,
            status="PENDING",
            scan_mode="STANDARD",
            enabled_modules_json='["headers"]'
        )
        from webscanpro import db
        db.session.add(scan)
        db.session.commit()

        # Mock crawler to return a single resource
        mock_resource = CrawledResource(
            url="http://127.0.0.1:5000/mock-lab/",
            path="/mock-lab/",
            method="GET",
            status_code=200,
            content_type="text/html",
            headers={"Server": "MockServer/1.0"}
        )

        with patch("webscanpro.core.engine.SafeCrawler") as MockCrawler:
            mock_crawler_inst = MagicMock()
            mock_crawler_inst.crawl.return_value = [mock_resource]
            mock_crawler_inst.request_count = 1
            mock_crawler_inst.session = MagicMock()
            MockCrawler.return_value = mock_crawler_inst

            # Run engine synchronously
            ScanEngine._run_scan_thread(app, scan.id)

        # Expire session cache and refresh scan
        db.session.expire_all()
        updated_scan = db.session.get(Scan, scan.id)
        assert updated_scan.status == "COMPLETED"
        assert updated_scan.endpoints_discovered == 1
        assert updated_scan.duration_seconds > 0
        assert updated_scan.findings.count() > 0
