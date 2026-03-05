# display.sh — Logging helpers for devicepass-cli
# Sourced by devicepass-cli

# Detect terminal for colors
if [ -t 1 ]; then
	_C_RED='\033[0;31m'
	_C_GREEN='\033[0;32m'
	_C_YELLOW='\033[0;33m'
	_C_BLUE='\033[0;34m'
	_C_RESET='\033[0m'
else
	_C_RED=''
	_C_GREEN=''
	_C_YELLOW=''
	_C_BLUE=''
	_C_RESET=''
fi

log_info() {
	printf "${_C_BLUE}[info]${_C_RESET} %s\n" "$*"
}

log_warn() {
	printf "${_C_YELLOW}[warn]${_C_RESET} %s\n" "$*" >&2
}

log_error() {
	printf "${_C_RED}[error]${_C_RESET} %s\n" "$*" >&2
}

log_success() {
	printf "${_C_GREEN}[ok]${_C_RESET} %s\n" "$*"
}
