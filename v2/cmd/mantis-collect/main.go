package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/SergioMazariego/Mantis/v2/internal/auth"
	"github.com/SergioMazariego/Mantis/v2/internal/casecore"
	"github.com/SergioMazariego/Mantis/v2/internal/collector"
	"github.com/SergioMazariego/Mantis/v2/internal/evidence"
	"github.com/SergioMazariego/Mantis/v2/internal/ingest"
	"github.com/SergioMazariego/Mantis/v2/internal/pkgexport"
	"github.com/SergioMazariego/Mantis/v2/internal/storage/sqlite"
)

// Set at build time: -ldflags "-X main.version=... -X main.commit=... -X main.date=...".
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// selectionContext is shown by the graphical selector; it is informational only.
var selectionContext struct {
	Case, Profile, Store, Evidence, Output string
	Elevated                               bool
}

// platformOptions are operator choices that individual platform collectors need.
type platformOptions struct {
	TempDir    string   // scratch directory for staged exports (inside the output directory)
	MemoryPIDs []uint32 // processes explicitly approved for memory dumps

	// Narrowing of the Windows Temp collection; all zero keeps every file.
	TempExtensions   []string
	TempTypes        []string
	TempMaxFileMB    int64
	TempModifiedDays int
	TempMaxFiles     int
	TempMaxDepth     int
}

// packageOutcome records the evidence package written by the last collection.
var packageOutcome struct {
	Dir     string
	Summary *pkgexport.Summary
	Err     error
}

func main() { os.Exit(run()) }

func run() int {
	caseIDValue := flag.String("case", "case-"+time.Now().UTC().Format("20060102T150405Z"), "case ID for this acquisition")
	tenantValue := flag.String("tenant", "local", "local tenant ID")
	actorValue := flag.String("actor", "local-analyst", "analyst ID")
	caseTitle := flag.String("title", "Local evidence collection", "title if creating a new case")
	maxTotal := flag.Int64("max-total-bytes", 0, "maximum bytes across this plan (0: profile default)")
	artifactIDs := flag.String("artifacts", "", "comma-separated source IDs to collect")
	listArtifacts := flag.Bool("list-artifacts", false, "list sources (category, privilege, profiles, availability) and exit")
	collectAll := flag.Bool("all", false, "explicitly collect every registered source (sensitive ones need --confirm-sensitive)")
	profileFlag := flag.String("profile", "", "acquisition profile: quick, standard or full")
	outputFlag := flag.String("output", "", "evidence package directory (default: next to the executable; must be NTFS)")
	confirmSensitive := flag.Bool("confirm-sensitive", false, "approve sources that are sensitive or alter the system")
	memoryPIDs := flag.String("memory-pids", "", "comma-separated PIDs approved for process memory dumps")
	tempExt := flag.String("temp-ext", "", "Windows Temp: keep only these extensions, comma-separated (e.g. exe,dll,ps1)")
	tempTypes := flag.String("temp-types", "", "Windows Temp: keep only these file types, matched by name or content signature: "+tempTypeNames)
	tempMaxMB := flag.Int64("temp-max-file-mb", 0, "Windows Temp: skip files larger than this many MiB (0: collector limit of 128)")
	tempDays := flag.Int("temp-modified-days", 0, "Windows Temp: keep only files modified in the last N days (0: any age)")
	tempFiles := flag.Int("temp-max-files", 0, "Windows Temp: stop after this many files (0: 8000)")
	tempDepth := flag.Int("temp-depth", 0, "Windows Temp: maximum folder depth (0: 6)")
	csvViews := flag.Bool("csv", false, "also write csv/ tables derived from the JSON snapshots (for reading without a viewer; not evidence)")
	force := flag.Bool("force", false, "continue even if free space looks insufficient")
	cliSelect := flag.Bool("cli", false, "select sources interactively in the terminal")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Printf("mantis-collect %s (commit %s, built %s, %s/%s)\n", version, commit, date, runtime.GOOS, runtime.GOARCH)
		return 0
	}
	if flag.NArg() != 0 || *maxTotal < 0 || *tempMaxMB < 0 || *tempDays < 0 || *tempFiles < 0 || *tempDepth < 0 {
		fmt.Fprintln(os.Stderr, "invalid arguments")
		return 2
	}
	var profile collector.Profile
	if *profileFlag != "" {
		p, ok := collector.ParseProfile(*profileFlag)
		if !ok || p == collector.ProfileCustom {
			fmt.Fprintln(os.Stderr, "unknown profile; use quick, standard or full (or select sources with --artifacts/--cli)")
			return 2
		}
		profile = p
	}
	if (*collectAll && *artifactIDs != "") || (profile != "" && (*collectAll || *artifactIDs != "")) {
		fmt.Fprintln(os.Stderr, "use only one of --profile, --all or --artifacts")
		return 2
	}
	pids, err := parsePIDs(*memoryPIDs)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	base := platformOptions{MemoryPIDs: pids, TempExtensions: splitList(*tempExt), TempTypes: splitList(*tempTypes),
		TempMaxFileMB: *tempMaxMB, TempModifiedDays: *tempDays, TempMaxFiles: *tempFiles, TempMaxDepth: *tempDepth}
	if err := platformConfigure(base); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	sources := platformSources()
	if len(sources) == 0 {
		fmt.Fprintln(os.Stderr, collector.ErrNoSources)
		return 1
	}
	_, elevated := platformHost()
	if *listArtifacts { // listing must not create or probe the output location on the target
		printCatalog(sources, elevated)
		return 0
	}
	outDir, err := resolveOutputDir(*outputFlag, *caseIDValue)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	dataDir := filepath.Join(outDir, ".mantis")
	base.TempDir = filepath.Join(dataDir, "tmp")
	if err := platformConfigure(base); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	forceCLISelection = *cliSelect
	selectionContext.Case, selectionContext.Profile = *caseIDValue, runtime.GOOS+".p0"
	selectionContext.Store, selectionContext.Evidence, selectionContext.Output = dataDir, filepath.Join(dataDir, "evidence"), outDir
	selectionContext.Elevated = elevated

	var selected []collector.Source
	var runNotes []string
	profileName := string(collector.ProfileCustom)
	switch {
	case profile != "":
		profileName = string(profile)
		selected = collector.SelectProfile(sources, profile, *confirmSensitive)
		if len(selected) == 0 {
			fmt.Fprintln(os.Stderr, collector.ErrNoSources)
			return 1
		}
		if !*confirmSensitive { // say which sensitive sources of the profile were left out, so the package does not read as complete
			var left []string
			for _, s := range collector.SelectProfile(sources, profile, true) {
				if s.Meta.Sensitive {
					left = append(left, s.ID)
				}
			}
			if len(left) > 0 {
				runNotes = append(runNotes, fmt.Sprintf("sensitive sources of the %s profile were not collected (no --confirm-sensitive): %s", profile, strings.Join(left, ", ")))
			}
		}
	case *collectAll:
		profileName = "all"
		for _, s := range sources {
			if !s.Meta.Sensitive || *confirmSensitive {
				selected = append(selected, s)
			}
		}
	case *artifactIDs != "":
		selected, err = selectByID(sources, strings.Split(*artifactIDs, ","))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
	}
	budget := *maxTotal
	if budget == 0 {
		budget = collector.DefaultMaxTotal(profile)
	}

	cfg := runConfig{caseID: *caseIDValue, tenant: *tenantValue, actor: *actorValue, title: *caseTitle, profile: profileName,
		outDir: outDir, dataDir: dataDir, budget: budget, force: *force, csv: *csvViews, notes: runNotes}
	guiCollect = func(ctx context.Context, chosen []collector.Source, onEvent func(collector.Event)) ([]collector.ItemResult, error) {
		run := cfg
		if profile == "" && !*collectAll && *artifactIDs == "" {
			// the window picked the sources: when they are exactly a built-in profile, record that profile and
			// apply its size budget, so the same selection gives the same package as the command line
			if name, p := matchProfile(sources, chosen); name != "" {
				run.profile = name
				if *maxTotal == 0 {
					run.budget = collector.DefaultMaxTotal(p)
				}
			}
		}
		return runCollection(ctx, run, chosen, onEvent)
	}

	if profile == "" && !*collectAll && *artifactIDs == "" {
		selected, err = selectSources(sources, os.Stdin, os.Stdout)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		if guiOutcome.Ran { // the graphical flow already collected (or was cancelled) in its own window
			return reportResults(guiOutcome.Results, guiOutcome.Err, *caseIDValue)
		}
	}
	if sens := collector.NeedsConfirmation(selected); len(sens) > 0 && !*confirmSensitive {
		fmt.Fprintln(os.Stderr, "these sources are sensitive or alter the system; rerun with --confirm-sensitive to approve them:")
		for _, s := range sens {
			fmt.Fprintf(os.Stderr, "  %s: %s\n", s.ID, s.Meta.SideEffects)
		}
		return 2
	}
	// Ctrl+C stops the acquisition and still exports what was already collected, like the Cancel button
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	results, err := runCollection(ctx, cfg, selected, nil)
	if ctx.Err() != nil {
		fmt.Fprintln(os.Stderr, "interrupted: the evidence acquired so far was exported")
	}
	return reportResults(results, err, *caseIDValue)
}

// matchProfile returns the built-in profile whose sources are exactly the chosen ones (sensitive
// sources excluded, as the profile buttons do), or "" when the selection is custom.
func matchProfile(all, chosen []collector.Source) (string, collector.Profile) {
	ids := map[string]bool{}
	for _, c := range chosen {
		ids[c.ID] = true
	}
	for _, p := range []collector.Profile{collector.ProfileQuick, collector.ProfileStandard, collector.ProfileFull} {
		want := collector.SelectProfile(all, p, false)
		if len(want) != len(ids) {
			continue
		}
		ok := true
		for _, w := range want {
			if !ids[w.ID] {
				ok = false
				break
			}
		}
		if ok {
			return string(p), p
		}
	}
	return "", ""
}

// usageError marks invalid operator input (exit code 2).
type usageError struct{ error }

// collectFunc runs one collection; the graphical selector calls it from its own window.
type collectFunc func(ctx context.Context, sources []collector.Source, onEvent func(collector.Event)) ([]collector.ItemResult, error)

var guiCollect collectFunc

// guiOutcome records a collection that the graphical window already ran.
var guiOutcome struct {
	Ran     bool
	Results []collector.ItemResult
	Err     error
}

type runConfig struct {
	caseID, tenant, actor, title, profile string
	outDir, dataDir                       string
	budget                                int64
	force                                 bool
	csv                                   bool     // derive csv/ views from the JSON snapshots
	notes                                 []string // run-level notes decided before collection (e.g. sensitive sources left out)
}

// runCollection stores evidence in the case store, then exports and verifies the
// evidence package. Evidence acquired before a cancellation is always exported.
func runCollection(ctx context.Context, cfg runConfig, sources []collector.Source, onEvent func(collector.Event)) ([]collector.ItemResult, error) {
	started := time.Now().UTC()
	packageOutcome.Dir, packageOutcome.Summary, packageOutcome.Err = cfg.outDir, nil, nil
	blobDir := filepath.Join(cfg.dataDir, "evidence")
	tmpDir := filepath.Join(cfg.dataDir, "tmp")
	// a package is written into an empty folder only: reusing one would mix (and overwrite) evidence of two runs
	if entries, err := os.ReadDir(cfg.outDir); err == nil {
		for _, e := range entries {
			if e.Name() != ".mantis" {
				return nil, usageError{fmt.Errorf("the output directory %s is not empty; choose a new folder for each package", cfg.outDir)}
			}
		}
	}
	for _, d := range []string{cfg.outDir, cfg.dataDir, tmpDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
	}
	defer os.RemoveAll(tmpDir)
	if err := checkHardLinks(cfg.dataDir); err != nil {
		return nil, fmt.Errorf("the output directory %s cannot hold the evidence store (NTFS hard links are required): %w", cfg.outDir, err)
	}
	notes := append([]string(nil), cfg.notes...)
	host, elevated := platformHost()
	if host["emulated_process"] == "true" {
		return nil, errors.New("this is a 32-bit process on 64-bit Windows: file system redirection would hide System32 artifacts; use the 64-bit build")
	}
	if sysDrive := os.Getenv("SystemDrive"); sysDrive != "" && strings.EqualFold(filepath.VolumeName(cfg.outDir), sysDrive) {
		notes = append(notes, "the evidence package is being written to the system volume being collected; prefer external or separate media for a defensible acquisition")
	}
	if !elevated {
		notes = append(notes, "mantis-collect is not elevated: sources that need administrator rights are reported as access_denied or unavailable")
	}
	if free, ok := platformFreeBytes(cfg.outDir); ok {
		if need := estimateNeeded(ctx, sources, cfg.budget); need > 0 && free < uint64(need)*2 {
			msg := fmt.Sprintf("free space on the output volume (%s) may be insufficient for the estimated evidence (%s, stored twice: case store and package)", humanSize(int64(free)), humanSize(need))
			if !cfg.force {
				return nil, errors.New(msg + "; choose another --output or pass --force")
			}
			notes = append(notes, msg)
		}
	}

	db, err := sqlite.Open(filepath.Join(cfg.dataDir, "cases.sqlite"))
	if err != nil {
		return nil, err
	}
	defer db.Close()
	tenant, err := casecore.NewTenantID(cfg.tenant)
	if err != nil {
		return nil, usageError{err}
	}
	caseID, err := casecore.NewCaseID(cfg.caseID)
	if err != nil {
		return nil, usageError{err}
	}
	actor, err := casecore.NewActorID(cfg.actor)
	if err != nil {
		return nil, usageError{err}
	}
	scope, err := casecore.NewScope(tenant, caseID, actor)
	if err != nil {
		return nil, usageError{err}
	}
	if _, err := db.LookupMembership(ctx, tenant, caseID, actor); errors.Is(err, auth.ErrMembershipNotFound) {
		if err := db.BootstrapCase(ctx, scope, cfg.title); err != nil {
			return nil, fmt.Errorf("case bootstrap: %w", err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("case membership: %w", err)
	}
	authorizer, err := auth.NewAuthorizer(db)
	if err != nil {
		return nil, err
	}
	blobs, err := evidence.OpenStore(blobDir)
	if err != nil {
		return nil, err
	}
	service, err := ingest.New(ctx, authorizer, blobs, db)
	if err != nil {
		return nil, err
	}
	runner, err := collector.NewRunner(service)
	if err != nil {
		return nil, err
	}
	hostID := host["hostname"]
	if hostID == "" {
		hostID = "local-host"
	}
	plan := collector.Plan{ID: "local-" + time.Now().UTC().Format("20060102T150405.000000000Z"), AssetID: hostID,
		Profile: runtime.GOOS + "." + cfg.profile, MaxTotalBytes: cfg.budget, Sources: sources}
	results, runErr := runner.RunObserved(ctx, scope, plan, onEvent)

	privilege := "user"
	if elevated {
		privilege = "admin"
	}
	if runErr != nil {
		notes = append(notes, "collection ended early: "+runErr.Error())
	}
	if n := platformFilterNote(); n != "" {
		notes = append(notes, n)
	}
	sum, exportErr := pkgexport.Write(context.Background(), pkgexport.Options{
		Dir: cfg.outDir, CaseID: cfg.caseID, TenantID: cfg.tenant, HostID: hostID, Host: host, ToolVersion: version,
		Profile: cfg.profile, Privilege: privilege, StartedAt: started, FinishedAt: time.Now().UTC(), Items: results,
		GlobalNotes: notes, SelectedOnly: cfg.profile != string(collector.ProfileFull) || len(cfg.notes) > 0, CSV: cfg.csv,
		Open: func(c context.Context, sha string) (io.ReadCloser, error) {
			return service.OpenVerified(c, scope, sha)
		},
	})
	packageOutcome.Summary, packageOutcome.Err = sum, exportErr
	if exportErr != nil && runErr == nil {
		return results, fmt.Errorf("evidence package: %w", exportErr)
	}
	return results, runErr
}

// checkHardLinks verifies that the evidence store directory supports hard links.
func checkHardLinks(dir string) error {
	a := filepath.Join(dir, ".linktest-a")
	b := filepath.Join(dir, ".linktest-b")
	os.Remove(a)
	os.Remove(b)
	if err := os.WriteFile(a, []byte("x"), 0o600); err != nil {
		return err
	}
	defer os.Remove(a)
	defer os.Remove(b)
	return os.Link(a, b)
}

// estimateNeeded sums the sources' own size estimates (capped by the plan budget).
func estimateNeeded(ctx context.Context, sources []collector.Source, budget int64) int64 {
	var total int64
	for _, s := range sources {
		if s.Estimate != nil {
			if n := s.Estimate(ctx); n > 0 {
				total += n
			}
		}
	}
	if total > budget {
		return budget
	}
	return total
}

func humanSize(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

// resolveOutputDir picks the evidence package directory. Running from removable
// media is the usual DFIR practice, so the default sits next to the executable;
// when that location is not writable it falls back to the user's Documents.
func resolveOutputDir(flagValue, caseID string) (string, error) {
	host, _ := os.Hostname()
	name := "Mantis-" + caseID + "-" + host + "-" + time.Now().UTC().Format("20060102T150405Z")
	if flagValue != "" {
		return filepath.Abs(flagValue)
	}
	var bases []string
	if exe, err := os.Executable(); err == nil {
		bases = append(bases, filepath.Dir(exe))
	}
	if home, err := os.UserHomeDir(); err == nil {
		bases = append(bases, filepath.Join(home, "Documents", "Mantis-Evidence"))
	}
	for _, base := range bases {
		if err := os.MkdirAll(base, 0o755); err != nil {
			continue
		}
		probe := filepath.Join(base, ".mantis-write-test")
		if err := os.WriteFile(probe, []byte("x"), 0o600); err != nil {
			continue
		}
		os.Remove(probe)
		return filepath.Join(base, name), nil
	}
	return "", errors.New("no writable location for the evidence package; pass --output")
}

const tempTypeNames = "executable, library, script, archive, document, shortcut"

// splitList turns "a, b,,c" into [a b c].
func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parsePIDs(s string) ([]uint32, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	var out []uint32
	for _, part := range strings.Split(s, ",") {
		n, err := strconv.ParseUint(strings.TrimSpace(part), 10, 32)
		if err != nil || n == 0 {
			return nil, fmt.Errorf("invalid PID %q in --memory-pids", part)
		}
		out = append(out, uint32(n))
	}
	return out, nil
}

func printCatalog(sources []collector.Source, elevated bool) {
	fmt.Printf("Elevated: %v\n", elevated)
	fmt.Printf("%-34s %-14s %-6s %-8s %-12s %s\n", "ID", "CATEGORY", "PRIV", "PROFILES", "AVAIL", "SOURCE")
	sorted := append([]collector.Source(nil), sources...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Meta.Category != sorted[j].Meta.Category {
			return sorted[i].Meta.Category < sorted[j].Meta.Category
		}
		return sorted[i].ID < sorted[j].ID
	})
	for _, s := range sorted {
		avail := "-"
		if s.Detect != nil {
			avail = string(s.Detect(context.Background()).State)
		}
		prof := ""
		for _, p := range []struct {
			m collector.ProfileMask
			c string
		}{{collector.InQuick, "Q"}, {collector.InStandard, "S"}, {collector.InFull, "F"}} {
			if s.Meta.Profiles&p.m != 0 {
				prof += p.c
			}
		}
		flags := ""
		if s.Meta.Sensitive {
			flags = " [sensitive]"
		}
		fmt.Printf("%-34s %-14s %-6s %-8s %-12s %s%s\n", s.ID, s.Meta.Category, s.Meta.Privilege, prof, avail, s.Locator, flags)
	}
}

func reportResults(results []collector.ItemResult, err error, caseID string) int {
	if err != nil && len(results) == 0 {
		fmt.Fprintln(os.Stderr, err)
		var usage usageError
		if errors.As(err, &usage) {
			return 2
		}
		return 1
	}
	failed := err != nil
	counts := map[collector.Disposition]int{}
	for _, item := range results {
		d := item.Classify()
		counts[d]++
		switch d {
		case collector.Collected, collector.CollectedWarnings, collector.Empty:
			fmt.Printf("%-24s %-30s sha256=%s bytes=%d\n", strings.ToUpper(string(d)), item.SourceID, item.Result.Blob.SHA256, item.Result.Blob.SizeBytes)
		case collector.DispNotPresent, collector.DispNotSupported:
			fmt.Printf("%-24s %-30s %v\n", "GAP:"+string(d), item.SourceID, item.Err)
		default:
			failed = true
			fmt.Printf("%-24s %-30s %v\n", "FAILED:"+string(d), item.SourceID, item.Err)
		}
	}
	fmt.Printf("Summary: %d collected, %d with warnings, %d empty, %d not present, %d not supported, %d access denied, %d failed, %d cancelled\n",
		counts[collector.Collected], counts[collector.CollectedWarnings], counts[collector.Empty], counts[collector.DispNotPresent],
		counts[collector.DispNotSupported], counts[collector.DispAccessDenied], counts[collector.DispFailed], counts[collector.DispCancelled])
	if packageOutcome.Summary != nil {
		state := "VERIFIED"
		if !packageOutcome.Summary.Verified {
			state = "VERIFICATION FAILED"
			failed = true
		}
		fmt.Printf("Evidence package: %s (%d files, %s) %s\n", packageOutcome.Dir, packageOutcome.Summary.Files, humanSize(packageOutcome.Summary.Bytes), state)
		for _, v := range packageOutcome.Summary.VerifyErrors[:min(len(packageOutcome.Summary.VerifyErrors), 10)] {
			fmt.Fprintln(os.Stderr, "  verification:", v)
		}
		if packageOutcome.Err != nil && len(packageOutcome.Summary.VerifyErrors) == 0 { // the package could not be written completely
			fmt.Fprintln(os.Stderr, "evidence package:", packageOutcome.Err)
		}
	} else if packageOutcome.Err != nil {
		fmt.Fprintln(os.Stderr, "evidence package:", packageOutcome.Err)
		failed = true
	}
	if failed {
		fmt.Printf("Collection finished with gaps. Case: %s\n", caseID)
		return 1
	}
	fmt.Printf("Collection complete for the selected sources. Case: %s\n", caseID)
	return 0
}

func selectByID(catalog []collector.Source, ids []string) ([]collector.Source, error) {
	lookup := make(map[string]collector.Source, len(catalog))
	for _, source := range catalog {
		lookup[source.ID] = source
	}
	selected := make([]collector.Source, 0, len(ids))
	seen := map[string]bool{}
	for _, raw := range ids {
		id := strings.TrimSpace(raw)
		if id == "" || seen[id] {
			return nil, fmt.Errorf("invalid or repeated artifact ID %q", id)
		}
		source, ok := lookup[id]
		if !ok {
			return nil, fmt.Errorf("unknown or unavailable artifact ID %q; use --list-artifacts", id)
		}
		seen[id] = true
		selected = append(selected, source)
	}
	if len(selected) == 0 {
		return nil, collector.ErrNoSources
	}
	return selected, nil
}

func selectSources(sources []collector.Source, input *os.File, output *os.File) ([]collector.Source, error) {
	return selectPlatformSources(sources, bufio.NewReader(input), output)
}

var forceCLISelection bool

func selectSourcesCLI(sources []collector.Source, input *bufio.Reader, output *os.File) ([]collector.Source, error) {
	if info, err := output.Stat(); err == nil && info.Mode()&os.ModeCharDevice == 0 {
		return nil, fmt.Errorf("interactive selection unavailable; provide --profile, --artifacts or --all")
	}
	fmt.Fprintln(output, "Available sources (comma-separated numbers, a profile name quick|standard|full, or all):")
	for index, source := range sources {
		fmt.Fprintf(output, "%3d) %-34s %-12s %s\n", index+1, source.ID, source.Meta.Category, source.Locator)
	}
	fmt.Fprint(output, "Select: ")
	line, err := input.ReadString('\n')
	if err != nil && len(line) == 0 {
		return nil, err
	}
	line = strings.TrimSpace(line)
	if strings.EqualFold(line, "all") {
		return sources, nil
	}
	if p, ok := collector.ParseProfile(line); ok && p != collector.ProfileCustom {
		return collector.SelectProfile(sources, p, false), nil
	}
	selected := make([]collector.Source, 0)
	seen := map[int]bool{}
	for _, raw := range strings.Split(line, ",") {
		index, parseErr := strconv.Atoi(strings.TrimSpace(raw))
		if parseErr != nil || index < 1 || index > len(sources) || seen[index] {
			return nil, fmt.Errorf("invalid selection %q", raw)
		}
		seen[index] = true
		selected = append(selected, sources[index-1])
	}
	if len(selected) == 0 {
		return nil, collector.ErrNoSources
	}
	return selected, nil
}
