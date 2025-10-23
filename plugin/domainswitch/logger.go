package domainswitch

import (
	"fmt"
	"io"
	golog "log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// LogWriter 日志写入器，支持按天自动切分
type LogWriter struct {
	logDir      string     // 日志目录
	logPrefix   string     // 日志文件前缀
	currentDate string     // 当前日期
	file        *os.File   // 当前日志文件
	mu          sync.Mutex // 互斥锁
	stdout      bool       // 是否同时输出到控制台
}

// NewLogWriter 创建新的日志写入器
// logPath: 日志文件路径，例如 "/var/log/coredns/coredns.log"
// stdout: 是否同时输出到控制台
func NewLogWriter(logPath string, stdout bool) (*LogWriter, error) {
	if logPath == "" {
		// 如果没有指定日志文件，只输出到控制台
		return &LogWriter{stdout: true}, nil
	}

	// 解析日志路径
	logDir := filepath.Dir(logPath)
	logFile := filepath.Base(logPath)
	logPrefix := logFile

	// 移除扩展名
	if ext := filepath.Ext(logFile); ext != "" {
		logPrefix = logFile[:len(logFile)-len(ext)]
	}

	// 创建日志目录
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return nil, fmt.Errorf("创建日志目录失败: %v", err)
	}

	lw := &LogWriter{
		logDir:    logDir,
		logPrefix: logPrefix,
		stdout:    stdout,
	}

	// 打开日志文件
	if err := lw.rotate(); err != nil {
		return nil, err
	}

	// 启动日志切分协程
	go lw.rotateDaily()

	return lw, nil
}

// Write 实现 io.Writer 接口
func (lw *LogWriter) Write(p []byte) (n int, err error) {
	lw.mu.Lock()
	defer lw.mu.Unlock()

	// 检查是否需要切换日志文件
	today := time.Now().Format("2006-01-02")
	if today != lw.currentDate && lw.file != nil {
		if err := lw.rotateNoLock(); err != nil {
			return 0, err
		}
	}

	// 写入日志文件
	if lw.file != nil {
		n, err = lw.file.Write(p)
		if err != nil {
			return n, err
		}
	}

	// 同时输出到控制台
	if lw.stdout {
		os.Stdout.Write(p)
	}

	return n, nil
}

// rotate 切换到新的日志文件
func (lw *LogWriter) rotate() error {
	lw.mu.Lock()
	defer lw.mu.Unlock()
	return lw.rotateNoLock()
}

// rotateNoLock 切换到新的日志文件（不加锁版本）
func (lw *LogWriter) rotateNoLock() error {
	today := time.Now().Format("2006-01-02")

	// 如果没有配置日志目录，只输出到控制台
	if lw.logDir == "" {
		lw.currentDate = today
		return nil
	}

	// 关闭旧文件
	if lw.file != nil {
		lw.file.Close()
	}

	// 生成新的日志文件名：prefix-2006-01-02.log
	filename := fmt.Sprintf("%s-%s.log", lw.logPrefix, today)
	filepath := filepath.Join(lw.logDir, filename)

	// 打开新文件（追加模式）
	file, err := os.OpenFile(filepath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("打开日志文件失败: %v", err)
	}

	lw.file = file
	lw.currentDate = today

	return nil
}

// rotateDaily 每天检查并切换日志文件
func (lw *LogWriter) rotateDaily() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		today := time.Now().Format("2006-01-02")
		if today != lw.currentDate {
			if err := lw.rotate(); err != nil {
				// 如果切换失败，输出错误到控制台
				fmt.Fprintf(os.Stderr, "[ERROR] 日志文件切换失败: %v\n", err)
			}
		}
	}
}

// Close 关闭日志文件
func (lw *LogWriter) Close() error {
	lw.mu.Lock()
	defer lw.mu.Unlock()

	if lw.file != nil {
		return lw.file.Close()
	}
	return nil
}

// PluginLogger 插件日志记录器
type PluginLogger struct {
	prefix string
	writer io.Writer
}

// NewPluginLogger 创建插件日志记录器
func NewPluginLogger(pluginName string, writer io.Writer) *PluginLogger {
	return &PluginLogger{
		prefix: "[" + pluginName + "] ",
		writer: writer,
	}
}

// Infof 输出 INFO 级别日志
func (pl *PluginLogger) Infof(format string, v ...interface{}) {
	golog.SetOutput(pl.writer)
	golog.Print("[INFO] ", pl.prefix, fmt.Sprintf(format, v...))
}

// Info 输出 INFO 级别日志
func (pl *PluginLogger) Info(v ...interface{}) {
	golog.SetOutput(pl.writer)
	golog.Print("[INFO] ", pl.prefix, fmt.Sprint(v...))
}

// Warningf 输出 WARNING 级别日志
func (pl *PluginLogger) Warningf(format string, v ...interface{}) {
	golog.SetOutput(pl.writer)
	golog.Print("[WARNING] ", pl.prefix, fmt.Sprintf(format, v...))
}

// Warning 输出 WARNING 级别日志
func (pl *PluginLogger) Warning(v ...interface{}) {
	golog.SetOutput(pl.writer)
	golog.Print("[WARNING] ", pl.prefix, fmt.Sprint(v...))
}

// Errorf 输出 ERROR 级别日志
func (pl *PluginLogger) Errorf(format string, v ...interface{}) {
	golog.SetOutput(pl.writer)
	golog.Print("[ERROR] ", pl.prefix, fmt.Sprintf(format, v...))
}

// Error 输出 ERROR 级别日志
func (pl *PluginLogger) Error(v ...interface{}) {
	golog.SetOutput(pl.writer)
	golog.Print("[ERROR] ", pl.prefix, fmt.Sprint(v...))
}

// Debugf 输出 DEBUG 级别日志
func (pl *PluginLogger) Debugf(format string, v ...interface{}) {
	golog.SetOutput(pl.writer)
	golog.Print("[DEBUG] ", pl.prefix, fmt.Sprintf(format, v...))
}

// Debug 输出 DEBUG 级别日志
func (pl *PluginLogger) Debug(v ...interface{}) {
	golog.SetOutput(pl.writer)
	golog.Print("[DEBUG] ", pl.prefix, fmt.Sprint(v...))
}
