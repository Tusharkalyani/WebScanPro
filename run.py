import argparse
from webscanpro import create_app, db
from webscanpro.core.sample_data import seed_demo_data, purge_demo_data

app = create_app("development")

def main():
    parser = argparse.ArgumentParser(description="WebScanPro — Web Application Security Testing Tool")
    parser.add_argument("--host", default="127.0.0.1", help="Host interface to bind (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5001, help="Port to listen on (default: 5001 - prevents macOS AirPlay conflict on 5000)")
    parser.add_argument("--seed-demo", action="store_true", help="Seed realistic sample assessment data labelled as DEMO DATA")
    parser.add_argument("--purge-demo", action="store_true", help="Purge any demo data from the database to retain only genuine scans")
    args = parser.parse_args()

    with app.app_context():
        db.create_all()
        if args.purge_demo:
            print("[+] Purging all demo assessment data from database...")
            count = purge_demo_data()
            print(f"[✓] Purged {count} demo scans successfully.")
        if args.seed_demo:
            print("[+] Seeding demo security assessment data...")
            seed_demo_data()
            print("[✓] Demo data seeded successfully.")

    print("=================================================================")
    print("  🛡️  WebScanPro — Web Application Security Testing Platform")
    print(f"  🌐 Running on: http://{args.host}:{args.port}")
    print(f"  🧪 Safe Mock Target Lab: http://{args.host}:{args.port}/mock-lab/")
    print("  ⚡ Authorized testing mode active. Loopback targets permitted.")
    print("=================================================================")
    app.run(host=args.host, port=args.port, debug=True)

if __name__ == "__main__":
    main()
