package collector

import "time"

// EventKind identifies a lifecycle event emitted while a plan runs.
type EventKind string

const (
	// EventPlanReady is emitted once, after group sources are expanded and the plan is valid.
	EventPlanReady EventKind = "plan_ready"
	// EventSourceStarted is emitted before a source is read.
	EventSourceStarted EventKind = "source_started"
	// EventSourceFinished is emitted after a source was ingested or failed.
	EventSourceFinished EventKind = "source_finished"
)

// PlannedSource names one executable item of the (expanded) plan.
type PlannedSource struct{ ID, Kind, Locator string }

// Event is a structured progress notification. Observers are called on the
// goroutine running the plan and must return quickly.
type Event struct {
	Kind     EventKind
	Time     time.Time
	Planned  []PlannedSource // EventPlanReady: every item that will run, in order
	Index    int             // started/finished: zero-based position in Planned
	Source   PlannedSource   // started/finished
	Item     ItemResult      // finished
	Duration time.Duration   // finished
}
