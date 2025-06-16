package log

// unit tests helper to check log messages
type TestLogger struct {
	Logger   *DefaultLogger
	Messages map[string][]string
	Level    LogLevel
}

func NewTestLogger() *TestLogger {
	return &TestLogger{
		Logger:   NewDefaultLogger(),
		Messages: make(map[string][]string),
		Level:    InfoLevel,
	}
}

func (m *TestLogger) Reset() {
	n := NewTestLogger()
	*m = *n
}

func (m *TestLogger) Panic(msg string, fields Fields) {
	m.Logger.Panic(msg, fields)
	m.Messages["panic"] = append(m.Messages["panic"], msg)
}

func (m *TestLogger) Fatal(msg string, fields Fields) {
	m.Logger.Fatal(msg, fields)
	m.Messages["fatal"] = append(m.Messages["fatal"], msg)
}

func (m *TestLogger) Error(msg string, fields Fields) {
	m.Logger.Error(msg, fields)
	m.Messages["error"] = append(m.Messages["error"], msg)
}

func (m *TestLogger) Warn(msg string, fields Fields) {
	m.Logger.Warn(msg, fields)
	m.Messages["warn"] = append(m.Messages["warn"], msg)
}

func (m *TestLogger) Info(msg string, fields Fields) {
	m.Logger.Info(msg, fields)
	m.Messages["info"] = append(m.Messages["info"], msg)
}

func (m *TestLogger) Debug(msg string, fields Fields) {
	m.Logger.Debug(msg, fields)
	m.Messages["debug"] = append(m.Messages["debug"], msg)
}

func (m *TestLogger) SetLevel(level LogLevel) {
	m.Logger.SetLevel(level)
	m.Level = level
}

func (m *TestLogger) GetLevel() LogLevel {
	m.Logger.GetLevel()
	return m.Level
}
