import sys, urllib.request

try:
    with urllib.request.urlopen("http://localhost:3000/", timeout=15) as r:
        print("HTTP", r.status)
        sys.exit(0 if r.status == 200 else 1)
except Exception as e:
    print("checker error:", e)
    sys.exit(2)
