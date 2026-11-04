import sys
import urllib.error
import urllib.request


try:
    with urllib.request.urlopen("http://localhost:8080/WebGoat", timeout=15) as r:
        print("HTTP", r.status)  # noqa: T201
        sys.exit(0 if r.status in (200, 302) else 1)
except urllib.error.HTTPError as e:
    print("HTTP", e.code)  # noqa: T201
    sys.exit(0 if e.code in (200, 302, 401, 403) else 1)
except (urllib.error.URLError, OSError) as e:
    print("checker error:", e)  # noqa: T201
    sys.exit(2)
