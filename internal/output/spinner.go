package output

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// defaultFrames is the standard braille spinner animation.
var defaultFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// Spinner renders an indeterminate progress indicator.
type Spinner struct {
	frames   []string
	interval time.Duration
	writer   io.Writer
	msg      string
	mu       sync.Mutex
	running  bool
	stop     chan struct{}
	frameIdx int
}

// NewSpinner creates a Spinner that writes to stderr.
func NewSpinner(msg string) *Spinner {
	return &Spinner{
		frames:   defaultFrames,
		interval: 100 * time.Millisecond,
		writer:   os.Stderr,
		msg:      msg,
	}
}

// SetWriter changes the output writer (useful for tests).
func (s *Spinner) SetWriter(w io.Writer) {
	s.writer = w
}

// SetFrames overrides the default animation frames (useful for tests).
func (s *Spinner) SetFrames(frames []string) {
	s.frames = frames
}

// SetInterval overrides the frame interval.
func (s *Spinner) SetInterval(d time.Duration) {
	s.interval = d
}

// SetFrameIdx sets the current frame index (useful for deterministic tests).
func (s *Spinner) SetFrameIdx(idx int) {
	s.frameIdx = idx
}

// Start begins the spinner animation. On non-TTY it prints a static message.
func (s *Spinner) Start() {
	if !Enabled() {
		fmt.Fprintf(s.writer, "%s...\n", s.msg)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		return
	}
	s.running = true
	s.stop = make(chan struct{})
	go s.loop()
}

// Stop halts the spinner and clears the line.
func (s *Spinner) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running {
		return
	}
	s.running = false
	close(s.stop)
	if Enabled() {
		// Clear the spinner line.
		frame := s.frames[s.frameIdx%len(s.frames)]
		lineLen := len(frame) + 1 + len(s.msg)
		fmt.Fprintf(s.writer, "\r%s\r", strings.Repeat(" ", lineLen))
	}
}

// Frame returns the current frame string without side effects.
func (s *Spinner) Frame() string {
	if !Enabled() {
		return fmt.Sprintf("%s...", s.msg)
	}
	frame := s.frames[s.frameIdx%len(s.frames)]
	return fmt.Sprintf("%s %s", frame, s.msg)
}

func (s *Spinner) loop() {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.mu.Lock()
			if !s.running {
				s.mu.Unlock()
				return
			}
			s.frameIdx++
			frame := s.Frame()
			s.mu.Unlock()
			fmt.Fprintf(s.writer, "\r%s", frame)
		case <-s.stop:
			return
		}
	}
}
