#!/bin/sh
# Build-time check: the image's ZAP must start and answer its API, as each scan expects.
# Started the same way as zap_adapter.py (daemon, -silent, fresh home directory).
# The build fails here instead of every ZAP scan failing at run time.
LIMIT=150
home=$(mktemp -d)
zap -daemon -silent -host 127.0.0.1 -port 8099 -dir "$home" -config api.disablekey=true > "$home/zap.log" 2>&1 &
ready=""
i=0
while [ $i -lt $LIMIT ]; do
    if wget -qO- http://127.0.0.1:8099/JSON/core/view/version/ > /dev/null 2>&1; then ready=$i; break; fi
    i=$((i + 1))
    sleep 1
done
if [ -n "$ready" ]; then
    echo "ZAP started in ${ready}s"
    if wget -qO- http://127.0.0.1:8099/JSON/ajaxSpider/view/status/ > /dev/null 2>&1; then
        echo "ZAP AJAX spider available"
    else
        echo "WARNING: ZAP AJAX spider not loaded, scans will use the classic spider only"
    fi
    wget -qO- http://127.0.0.1:8099/JSON/core/action/shutdown/ > /dev/null 2>&1
    sleep 5
fi
if [ -z "$ready" ]; then
    echo "ZAP did not answer within ${LIMIT}s. End of its log:"
    tail -40 "$home/zap.log"
    rm -rf "$home"
    exit 1
fi
rm -rf "$home"
