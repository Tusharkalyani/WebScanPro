import requests
from config import Config

class LabHealthChecker:
    @staticmethod
    def check_lab_status(lab_key: str = None) -> dict:
        presets = Config.LAB_PRESETS
        results = {}

        keys_to_check = [lab_key] if lab_key and lab_key in presets else presets.keys()

        for key in keys_to_check:
            info = presets[key]
            url = info["url"]
            try:
                resp = requests.get(url, timeout=2.5, verify=False)
                results[key] = {
                    "name": info["name"],
                    "url": url,
                    "description": info["description"],
                    "status": "ONLINE",
                    "status_code": resp.status_code,
                    "response_time_ms": int(resp.elapsed.total_seconds() * 1000),
                    "setup_cmd": LabHealthChecker.get_setup_command(key)
                }
            except requests.exceptions.RequestException:
                results[key] = {
                    "name": info["name"],
                    "url": url,
                    "description": info["description"],
                    "status": "OFFLINE",
                    "status_code": None,
                    "response_time_ms": None,
                    "setup_cmd": LabHealthChecker.get_setup_command(key)
                }
        return results

    @staticmethod
    def get_setup_command(key: str) -> str:
        commands = {
            "juice_shop": "docker run -d -p 3000:3000 bkimminich/juice-shop",
            "dvwa": "docker run -d -p 4280:80 vulnerables/web-dvwa",
            "mock_lab": "Built into WebScanPro! Available at /mock-lab/ or run 'python run_mock_lab.py'",
        }
        return commands.get(key, "")
