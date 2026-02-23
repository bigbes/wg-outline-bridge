# WireGuard-Outline Bridge development tasks

set dotenv-load
set unstable

# Remote host for deployment (must be set in .env)
remote_host := env("REMOTE_HOST")

# Remote paths (match systemd service)
remote_bin := env("REMOTE_BIN", "/data/bin/bridge")
remote_config_example := env("REMOTE_CONFIG_EXAMPLE", "/data/etc/bridge.conf.example")
remote_log := env("REMOTE_LOG", "/data/var/log/bridge.log")

# Local paths
local_bin := "bridge"
local_config := "configs/example.yaml"

# Version from git describe (tag + commits since tag + short hash)
version := `git describe --tags --long --always 2>/dev/null || echo "dev"`
ldflags := "-X main.Version=" + version

# Build the bridge binary (uses GOOS/GOARCH/CGO_ENABLED from .env)
build:
    go build -ldflags '{{ ldflags }}' -o {{ local_bin }} ./cmd/bridge/main.go

# Build for the local platform (ignores .env cross-compile settings)
build-local:
    GOOS="" GOARCH="" CGO_ENABLED="" go build -ldflags '{{ ldflags }}' -o {{ local_bin }} ./cmd/bridge/main.go

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

status:
    ssh {{ remote_host }} sudo systemctl status bridge

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

# Fetch pprof profiles from remote bridge
# Parameters: profile list (comma-separated), port (default 6060)
pprof profile='goroutine,heap' port='6060':
    mkdir -p ./pprof
    # Split profile list and fetch each using xargs (more reliable than shell loop)
    echo {{ profile }} | tr ',' '\n' | xargs -I {} sh -c '\
        echo "Fetching {} profile from {{ remote_host }}:{{ port }}"; \
        ssh {{ remote_host }} "curl -s http://localhost:{{ port }}/debug/pprof/{}" > ./pprof/{}.pprof; \
        echo "Saved ./pprof/{}.pprof"'

# Fetch pprof profiles via SSH tunnel (if bridge not directly accessible)
# Parameters: profile list (comma-separated), port (default 6060), local tunnel port (default 16060)
pprof-tunnel profile='goroutine,heap' port='6060' local_port='16060':
    # Create SSH tunnel, fetch profiles locally, then kill tunnel
    ssh -f -L {{ local_port }}:localhost:{{ port }} {{ remote_host }} sleep 10
    sleep 1  # wait for tunnel to establish
    mkdir -p ./pprof
    # Split profile list and fetch each using xargs
    echo {{ profile }} | tr ',' '\n' | xargs -I {} sh -c '\
        echo "Fetching {} profile via tunnel localhost:{{ local_port }}"; \
        curl -s http://localhost:{{ local_port }}/debug/pprof/{} > ./pprof/{}.pprof; \
        echo "Saved ./pprof/{}.pprof"'

# Fetch pprof profiles from local bridge instance
# Parameters: profile list (comma-separated), port (default 6060)
pprof-local profile='goroutine,heap' port='6060':
    mkdir -p ./pprof
    # Split profile list and fetch each using xargs
    echo {{ profile }} | tr ',' '\n' | xargs -I {} sh -c '\
        echo "Fetching {} profile from localhost:{{ port }}"; \
        curl -s http://localhost:{{ port }}/debug/pprof/{} > ./pprof/{}.pprof; \
        echo "Saved ./pprof/{}.pprof"'

# Fetch goroutine debug dump (text format with ?debug=2) from remote bridge
# Parameters: port (default 6060)
pprof-goroutines-debug port='6060':
    mkdir -p ./pprof
    echo "Fetching goroutine debug dump from {{ remote_host }}:{{ port }}"
    ssh {{ remote_host }} "curl -s 'http://localhost:{{ port }}/debug/pprof/goroutine?debug=2'" > ./pprof/goroutine-debug.txt
    echo "Saved ./pprof/goroutine-debug.txt"

# Fetch goroutine debug dump via SSH tunnel
# Parameters: port (default 6060), local tunnel port (default 16060)
pprof-goroutines-debug-tunnel port='6060' local_port='16060':
    # Create SSH tunnel, fetch debug dump locally, then kill tunnel
    ssh -f -L {{ local_port }}:localhost:{{ port }} {{ remote_host }} sleep 10
    sleep 1  # wait for tunnel to establish
    mkdir -p ./pprof
    echo "Fetching goroutine debug dump via tunnel localhost:{{ local_port }}"
    curl -s "http://localhost:{{ local_port }}/debug/pprof/goroutine?debug=2" > ./pprof/goroutine-debug.txt
    echo "Saved ./pprof/goroutine-debug.txt"
    # Tunnel will close automatically after sleep

# Fetch goroutine debug dump from local bridge instance
# Parameters: port (default 6060)
pprof-goroutines-debug-local port='6060':
    mkdir -p ./pprof
    echo "Fetching goroutine debug dump from localhost:{{ port }}"
    curl -s "http://localhost:{{ port }}/debug/pprof/goroutine?debug=2" > ./pprof/goroutine-debug.txt
    echo "Saved ./pprof/goroutine-debug.txt"


