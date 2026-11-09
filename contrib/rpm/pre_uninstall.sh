# Only on removal, not on upgrade
if [ "$1" -eq 0 ]; then
	systemctl disable --now yggdrasil.service >/dev/null 2>&1 || :
fi
