from bs4 import BeautifulSoup
from webscanpro.core.crawler import SafeCrawler

def test_crawler_origin_boundary():
    crawler = SafeCrawler(base_url="http://localhost:3000")
    assert crawler.is_same_origin("http://localhost:3000/profile") is True
    assert crawler.is_same_origin("http://localhost:3000/search?q=1") is True
    assert crawler.is_same_origin("http://localhost:4000/api") is False
    assert crawler.is_same_origin("https://localhost:3000/") is False
    assert crawler.is_same_origin("http://google.com") is False

def test_crawler_skip_media_and_logout():
    crawler = SafeCrawler(base_url="http://localhost:3000")
    assert crawler.should_skip_path("http://localhost:3000/logo.png") is True
    assert crawler.should_skip_path("http://localhost:3000/style.css") is True
    assert crawler.should_skip_path("http://localhost:3000/auth/logout") is True
    assert crawler.should_skip_path("http://localhost:3000/signout?token=123") is True
    assert crawler.should_skip_path("http://localhost:3000/products") is False

def test_crawler_canonicalization():
    crawler = SafeCrawler(base_url="http://localhost:3000")
    c1 = crawler.canonicalize_url("http://localhost:3000/search?b=2&a=1#section")
    c2 = crawler.canonicalize_url("http://localhost:3000/search?a=1&b=2")
    assert c1 == c2

def test_crawler_extract_forms():
    crawler = SafeCrawler(base_url="http://localhost:3000")
    html = """
    <html>
        <body>
            <form action="/login" method="POST">
                <input type="text" name="user" value="alice">
                <input type="password" name="pass" value="">
                <button type="submit">Submit</button>
            </form>
        </body>
    </html>
    """
    soup = BeautifulSoup(html, "html.parser")
    forms = crawler.extract_forms(soup, "http://localhost:3000/")
    assert len(forms) == 1
    assert forms[0]["action"] == "http://localhost:3000/login"
    assert forms[0]["method"] == "POST"
    assert len(forms[0]["inputs"]) == 2
    assert forms[0]["inputs"][0]["name"] == "user"
    assert forms[0]["inputs"][1]["name"] == "pass"
