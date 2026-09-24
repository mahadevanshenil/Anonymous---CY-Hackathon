# Hosts explicitly approved for scanning (lab targets only).
# Private/loopback IPs are always allowed; anything else must be listed here.
ALLOWED_HOSTS = {
    "localhost",
    "juice-shop.lab.local",   # example lab host: replace with yours
}
REQUEST_TIMEOUT = 5
