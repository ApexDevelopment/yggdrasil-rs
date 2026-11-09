getent group yggdrasil >/dev/null || groupadd --system yggdrasil
systemctl daemon-reload >/dev/null 2>&1 || :
