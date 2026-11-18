from flask import Blueprint, request, make_response, render_template_string, jsonify

mock_lab_bp = Blueprint("mock_lab", __name__)

MOCK_HTML_INDEX = """
<!DOCTYPE html>
<html>
<head>
    <title>WebScanPro Mock Target Lab</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; padding: 2rem; }
        .card { background: #1e293b; border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; border: 1px solid #334155; }
        h1 { color: #38bdf8; }
        a { color: #38bdf8; text-decoration: none; }
        a:hover { text-decoration: underline; }
        input, button { padding: 0.5rem; border-radius: 4px; border: 1px solid #475569; background: #0f172a; color: #fff; }
        button { background: #0284c7; cursor: pointer; border: none; }
        code { background: #0f172a; padding: 2px 6px; border-radius: 4px; color: #f43f5e; }
    </style>
</head>
<body>
    <h1>WebScanPro Mock Target Lab</h1>
    <p>This is a safe, local security test bench built into WebScanPro to verify scanner modules out of the box.</p>
    
    <div class="card">
        <h3>1. Search Endpoint (Reflected Input / XSS)</h3>
        <p>Path: <code>/mock-lab/search?q=test</code></p>
        <form action="/mock-lab/search" method="GET">
            <input type="text" name="q" placeholder="Search keywords..." value="security">
            <button type="submit">Search</button>
        </form>
    </div>

    <div class="card">
        <h3>2. Product Catalog (SQL Injection Simulation)</h3>
        <p>Path: <code>/mock-lab/products?category=electronics</code></p>
        <a href="/mock-lab/products?category=electronics">View Electronics</a> | 
        <a href="/mock-lab/products?category=books">View Books</a>
    </div>

    <div class="card">
        <h3>3. User Profiles (IDOR / Broken Access Control)</h3>
        <p>Path: <code>/mock-lab/profile/1</code></p>
        <a href="/mock-lab/profile/1">Alice's Profile (ID 1)</a> | 
        <a href="/mock-lab/profile/2">Bob's Profile (ID 2)</a>
    </div>

    <div class="card">
        <h3>4. Authentication & Session</h3>
        <p>Login with sample credentials: <code>alice / password123</code></p>
        <form action="/mock-lab/login" method="POST">
            <input type="text" name="username" placeholder="Username" value="alice">
            <input type="password" name="password" placeholder="Password" value="password123">
            <button type="submit">Sign In</button>
        </form>
    </div>
</body>
</html>
"""

@mock_lab_bp.route("/")
def index():
    resp = make_response(render_template_string(MOCK_HTML_INDEX))
    # Deliberately expose server version banner and omit security headers
    resp.headers["Server"] = "MockLabServer/2.4.1 (Ubuntu)"
    resp.headers["X-Powered-By"] = "Python/3.14-Flask"
    # Set a cookie missing HttpOnly and SameSite
    resp.set_cookie("mock_session", "demo1001", httponly=False, samesite=None)
    return resp

@mock_lab_bp.route("/search", methods=["GET"])
def search():
    query = request.args.get("q", "")
    # Deliberately reflect user query raw without HTML escaping
    html = f"""
    <!DOCTYPE html>
    <html>
    <head><title>Search Results</title></head>
    <body style="background:#0f172a; color:#fff; font-family:sans-serif; padding:2rem;">
        <h2>Search Results for: {query}</h2>
        <p>No results found for query.</p>
        <a href="/mock-lab/" style="color:#38bdf8;">Back to Lab</a>
    </body>
    </html>
    """
    return make_response(html)

@mock_lab_bp.route("/products", methods=["GET"])
def products():
    category = request.args.get("category", "")
    # Check for single quote or double quote to simulate SQLite operational syntax error safely
    if "'" in category or '"' in category:
        err_msg = 'sqlite3.OperationalError: near "\'": syntax error in SELECT * FROM products WHERE category = \'' + category + "'"
        return make_response(f"<h3>Database Error Encountered</h3><pre>{err_msg}</pre>", 500)
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <body style="background:#0f172a; color:#fff; font-family:sans-serif; padding:2rem;">
        <h2>Category: {category}</h2>
        <ul>
            <li>Product A - $19.99</li>
            <li>Product B - $29.99</li>
        </ul>
        <a href="/mock-lab/" style="color:#38bdf8;">Back to Lab</a>
    </body>
    </html>
    """
    return make_response(html)

PROFILES = {
    "1": {"id": 1, "username": "alice", "email": "alice@example-lab.internal", "role": "admin", "balance": "$5,240.00"},
    "2": {"id": 2, "username": "bob", "email": "bob@example-lab.internal", "role": "user", "balance": "$120.00"},
}

@mock_lab_bp.route("/profile/<user_id>", methods=["GET"])
def profile(user_id):
    # Unauthenticated / unvalidated object access
    user_data = PROFILES.get(str(user_id))
    if user_data:
        return jsonify(user_data)
    return jsonify({"error": "User not found"}), 404

@mock_lab_bp.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    resp = make_response(f"Welcome, {username}! Logged in successfully.")
    # Insecure session cookie (no HttpOnly, no Secure)
    resp.set_cookie("user_token", "1001", httponly=False)
    return resp

@mock_lab_bp.route("/logout", methods=["GET"])
def logout():
    # Deliberately fails to clear or invalidate session token on server
    return make_response("Logged out successfully.")
