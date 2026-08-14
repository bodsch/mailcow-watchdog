package probe

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// Mailq reports the size of postfix's deferred queue.
//
// It replaces `find /var/spool/postfix/deferred -type f | wc -l`, walking the
// hashed subdirectories postfix spreads its queue files across. The spool is
// mounted into the watchdog container read-only.
type Mailq struct {
	name     string
	dir      string
	critical int
}

// NewMailq returns a queue size probe that fails once the deferred queue holds
// critical or more messages (MAILQ_CRIT).
func NewMailq(name, dir string, critical int) *Mailq {
	return &Mailq{name: name, dir: dir, critical: critical}
}

// Name implements Probe.
func (p *Mailq) Name() string { return p.name }

// Run implements Probe.
func (p *Mailq) Run(ctx context.Context) Result {
	count, err := countFiles(ctx, p.dir)
	switch {
	case os.IsNotExist(err):
		// Postfix creates the directory lazily, so an absent spool means an
		// empty queue rather than a broken mount.
		count = 0
	case err != nil:
		return Unknown("%s: cannot read the deferred queue at %s: %v", p.name, p.dir, err)
	}

	if count >= p.critical {
		return Critical("%s: mail queue contains %d items (critical limit is %d)",
			p.name, count, p.critical)
	}
	return OK("%s: mail queue contains %d items (critical limit is %d)",
		p.name, count, p.critical)
}

// countFiles walks dir and counts regular files. Unreadable subdirectories are
// skipped rather than aborting the walk, because postfix renames queue files
// underneath us all the time.
func countFiles(ctx context.Context, dir string) (int, error) {
	if _, err := os.Stat(dir); err != nil {
		return 0, err
	}

	count := 0
	err := filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.Type().IsRegular() {
			count++
		}
		return nil
	})
	if err != nil {
		return count, fmt.Errorf("walking %s: %w", dir, err)
	}
	return count, nil
}
