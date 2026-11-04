import sys
import urllib.error
import urllib.request


try:
    with urllib.request.urlopen("http://localhost:4280/", timeout=15) as r:
        print("HTTP", r.status)  # noqa: T201
        sys.exit(0 if r.status == 200 else 1)
except urllib.error.URLError as e:
    print("checker error:", e)  # noqa: T201
    sys.exit(2)
except OSError as e:
    print("checker error:", e)  # noqa: T201
    sys.exit(2)
