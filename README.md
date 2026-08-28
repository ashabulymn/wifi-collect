# LJN NOC WiFi Collector

Web collector for authorized network inventory. Upload a text file containing one modem/ONT IP address per line, then collect exposed Wi-Fi/PPPoE information through the device's web interface.

## Features

- Web dashboard
- Bulk IP input/upload
- Configurable credential profiles through environment variables
- HTTP/HTTPS discovery
- Basic generic web-form login detection
- Heuristic extraction of SSID, Wi-Fi password/passphrase, and PPPoE username
- CSV export
- Concurrent collection with configurable worker count
- Private-IP-only safety default

## Run with Docker

```bash
cp .env.example .env
# Edit .env and use credentials authorized by your organization
docker compose up -d --build
```

Open `http://SERVER_IP:8080`.

## Important limitations

This is a generic collector, not a universal modem parser. Vendor firmware differs substantially. For reliable production collection, add vendor/model-specific adapters under `app/` after testing against the exact firmware used by the network.

The application intentionally does not bypass authentication, exploit firmware, or brute-force arbitrary credentials. Keep the service on a protected management network and do not expose port 8080 to the public Internet.

## Credentials

Credentials are supplied through environment variables and are not written into the result file. Change the example values before use.

## Data handling

Wi-Fi passwords are sensitive network credentials. Restrict access to the dashboard and exported CSV files and follow your organization's retention/access policy.
