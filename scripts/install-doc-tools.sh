#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
	printf 'Run as root (for example: sudo %s)\n' "$0" >&2
	exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y poppler-utils tesseract-ocr tesseract-ocr-eng

# The runtime intentionally reads one fixed English data path. Ubuntu 22.04
# packages Tesseract 4 data below 4.00; copy that packaged file to the fixed
# runtime path instead of making runtime discovery depend on distro layout.
fixed_data=/usr/share/tesseract-ocr/5/tessdata/eng.traineddata
tesseract_version="$(/usr/bin/tesseract --version | head -n 1)"
case "$tesseract_version" in
	"tesseract 4."*) source_data=/usr/share/tesseract-ocr/4.00/tessdata/eng.traineddata ;;
	"tesseract 5."*) source_data=/usr/share/tesseract-ocr/5/tessdata/eng.traineddata ;;
	*)
		printf 'Unsupported Tesseract version: %s\n' "$tesseract_version" >&2
		exit 1
		;;
esac
if [[ ! -s "$source_data" ]] || ! dpkg-query -S "$source_data" >/dev/null 2>&1; then
	printf 'English trained data is missing from the installed Tesseract package: %s\n' "$source_data" >&2
	exit 1
fi
if [[ "$source_data" != "$fixed_data" ]]; then
	install -D -o root -g root -m 0644 "$source_data" "$fixed_data"
else
	chown root:root "$fixed_data"
	chmod 0644 "$fixed_data"
fi

printf '\nPDF text tools:\n'
/usr/bin/pdftotext -v 2>&1 | head -n 1
/usr/bin/pdfinfo -v 2>&1 | head -n 1
/usr/bin/pdftoppm -v 2>&1 | head -n 1
printf '\nOCR tools:\n'
printf '%s\n' "$tesseract_version"
test -s "$fixed_data"
test "$(stat -c '%U:%G:%a' "$fixed_data")" = "root:root:644"
printf 'English trained data: installed\n'
