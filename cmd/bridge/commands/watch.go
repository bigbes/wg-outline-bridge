package commands

import (
	"context"
	"flag"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/blikh/wireguard-outline-bridge/internal/config"
)

func Watch(args []string, logger *slog.Logger) {
	fs := flag.NewFlagSet("watch", flag.ExitOnError)
	configPath := fs.String("config", "configs/bridge.yaml", "path to config file")
	logPath := fs.String("log", "output.log", "path to output log file")
	fs.Parse(args)

	_, migrated, err := config.Migrate(*configPath)
	if err != nil {
		logger.Error("failed to load config", "err", err)
		os.Exit(1)
	}
	if migrated {
		logger.Info("config migrated with new fields", "path", *configPath)
	}

	execPath, err := os.Executable()
	if err != nil {
		logger.Error("failed to get executable path", "err", err)
		os.Exit(1)
	}
	execPath, err = filepath.EvalSymlinks(execPath)
	if err != nil {
		logger.Error("failed to resolve executable path", "err", err)
		os.Exit(1)
	}

	logFile, err := os.OpenFile(*logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		logger.Error("failed to open log file", "err", err, "path", *logPath)
		os.Exit(1)
	}
	defer logFile.Close()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	w := &watcher{
		execPath:   execPath,
		configPath: *configPath,
		logFile:    logFile,
		logger:     logger,
	}
	w.run(ctx)
}

type watcher struct {
	execPath   string
	configPath string
	logFile    *os.File
	logger     *slog.Logger

	mu        sync.Mutex
	cmd       *exec.Cmd
	cmdCtx    context.Context
	cmdCancel context.CancelFunc
}

func (w *watcher) run(ctx context.Context) {
	w.logger.Info("watcher started", "binary", w.execPath, "config", w.configPath)

	lastMod := w.getModTime()
	w.startSubprocess()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			w.logger.Info("watcher stopping")
			w.stopSubprocess()
			return
		case <-ticker.C:
			currentMod := w.getModTime()
			if !currentMod.IsZero() && !lastMod.IsZero() && currentMod.After(lastMod) {
				w.logger.Info("binary updated, restarting subprocess", "old", lastMod, "new", currentMod)
				lastMod = currentMod
				w.restartSubprocess()
			}
		}
	}
}

func (w *watcher) getModTime() time.Time {
	info, err := os.Stat(w.execPath)
	if err != nil {
		w.logger.Debug("failed to stat binary", "err", err)
		return time.Time{}
	}
	return info.ModTime()
}

func (w *watcher) startSubprocess() {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.cmdCtx, w.cmdCancel = context.WithCancel(context.Background())

	w.cmd = exec.CommandContext(w.cmdCtx, w.execPath, "run", "--config", w.configPath)

	stdout, err := w.cmd.StdoutPipe()
	if err != nil {
		w.logger.Error("failed to create stdout pipe", "err", err)
		return
	}
	stderr, err := w.cmd.StderrPipe()
	if err != nil {
		w.logger.Error("failed to create stderr pipe", "err", err)
		return
	}

	go io.Copy(io.MultiWriter(w.logFile, os.Stdout), stdout)
	go io.Copy(io.MultiWriter(w.logFile, os.Stderr), stderr)

	w.logger.Info("starting subprocess")
	if err := w.cmd.Start(); err != nil {
		w.logger.Error("failed to start subprocess", "err", err)
		return
	}

	go func() {
		err := w.cmd.Wait()
		if err != nil && w.cmdCtx.Err() == nil {
			w.logger.Error("subprocess exited", "err", err)
		}
	}()
}

func (w *watcher) stopSubprocess() {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.cmdCancel != nil {
		w.cmdCancel()
	}
	if w.cmd != nil && w.cmd.Process != nil {
		w.cmd.Process.Signal(syscall.SIGTERM)
		done := make(chan struct{})
		go func() {
			w.cmd.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			w.logger.Warn("force killing subprocess")
			w.cmd.Process.Kill()
		}
	}
}

func (w *watcher) restartSubprocess() {
	w.stopSubprocess()
	time.Sleep(500 * time.Millisecond)
	w.startSubprocess()
}
