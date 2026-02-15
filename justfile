# WireGuard-Outline Bridge development tasks

set dotenv-load

# Remote host for deployment (must be set in .env)
remote_host := env("REMOTE_HOST")

# Remote paths (match systemd service)
remote_bin := env("REMOTE_BIN", "/data/bin/bridge")
remote_config_example := env("REMOTE_CONFIG_EXAMPLE", "/data/etc/bridge.conf.example")
remote_log := env("REMOTE_LOG", "/data/var/log/bridge.log")

# Local paths
local_bin := "main"
local_config := "configs/example.yaml"

# Build the bridge binary
build:
    go build -o {{ local_bin }} ./cmd/bridge/main.go

# Run all tests
test:
    go test ./...

# Run tests with verbose output
test-verbose:
    go test -v ./...

# Run tests with race detection
test-race:
    go test -race ./...

# Format and vet code
lint:
    go fmt ./...
    go vet ./...

# Upload binary and config example to remote host
upload: build
    scp {{ local_bin }} {{ remote_host }}:{{ remote_bin }}
    scp {{ local_config }} {{ remote_host }}:{{ remote_config_example }}

# Upload only the binary
upload-bin: build
    scp {{ local_bin }} {{ remote_host }}:{{ remote_bin }}

# Upload only the config example
upload-config:
    scp {{ local_config }} {{ remote_host }}:{{ remote_config_example }}

# Fetch logs from remote host
logs:
    scp {{ remote_host }}:{{ remote_log }} ./output.log

# Restart the remote service
restart:
    ssh {{ remote_host }} sudo systemctl restart bridge

# Stop the remote service
stop:
    ssh {{ remote_host }} sudo systemctl stop bridge

# Start the remote service
start:
    ssh {{ remote_host }} sudo systemctl start bridge

# Upload systemd unit file and reload daemon
upload-unit:
    scp configs/bridge.service {{ remote_host }}:/etc/systemd/system/bridge.service
    ssh {{ remote_host }} sudo systemctl daemon-reload

# Deploy: build, upload, and restart
deploy: upload restart

# Full redeploy: stop service, upload binary + config example, start service
redeploy: build stop upload start
