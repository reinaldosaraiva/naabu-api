package worker

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
)

// JobType represents different types of jobs
type JobType string

const (
	JobTypeQuickScan JobType = "quick_scan"
	JobTypeProbe     JobType = "probe"
	JobTypeDeepScan  JobType = "deep_scan"
)

// Job represents a work item
type Job struct {
	ID       string
	Type     JobType
	ScanID   string
	Payload  interface{}
	Priority int
	Retry    int
	MaxRetry int
}

// Worker represents a worker goroutine
type Worker struct {
	ID         int
	JobQueue   chan Job
	WorkerPool chan chan Job
	QuitChan   chan bool
	Logger     *zap.Logger
	Handler    JobHandler
}

// JobHandler defines the interface for handling different job types
type JobHandler interface {
	HandleJob(ctx context.Context, job Job) error
}

// Pool represents a worker pool
type Pool struct {
	workers    []*Worker
	jobQueue   chan Job
	workerPool chan chan Job
	quit       chan bool
	wg         sync.WaitGroup
	logger     *zap.Logger
	handler    JobHandler
	maxWorkers int
	maxQueue   int
}

// NewPool creates a new worker pool
func NewPool(maxWorkers, maxQueue int, handler JobHandler, logger *zap.Logger) *Pool {
	return &Pool{
		workerPool: make(chan chan Job, maxWorkers),
		jobQueue:   make(chan Job, maxQueue),
		quit:       make(chan bool),
		logger:     logger,
		handler:    handler,
		maxWorkers: maxWorkers,
		maxQueue:   maxQueue,
	}
}

// Start starts the worker pool
func (p *Pool) Start(ctx context.Context) {
	p.logger.Info("Starting worker pool",
		zap.Int("max_workers", p.maxWorkers),
		zap.Int("max_queue", p.maxQueue),
	)

	// Create and start workers
	for i := 0; i < p.maxWorkers; i++ {
		worker := &Worker{
			ID:         i + 1,
			JobQueue:   make(chan Job),
			WorkerPool: p.workerPool,
			QuitChan:   make(chan bool),
			Logger:     p.logger,
			Handler:    p.handler,
		}
		p.workers = append(p.workers, worker)
		p.wg.Add(1)
		go worker.Start(ctx, &p.wg)
	}

	// Start dispatcher
	p.wg.Add(1)
	go p.dispatch(ctx, &p.wg)
}

// Stop stops the worker pool gracefully
func (p *Pool) Stop() {
	p.logger.Info("Stopping worker pool")
	
	// Signal all workers to quit
	for _, worker := range p.workers {
		worker.QuitChan <- true
	}
	
	// Signal dispatcher to quit
	close(p.quit)
	
	// Wait for all workers to finish
	p.wg.Wait()
	
	p.logger.Info("Worker pool stopped")
}

// Submit submits a job to the pool
func (p *Pool) Submit(job Job) error {
	select {
	case p.jobQueue <- job:
		p.logger.Debug("Job submitted",
			zap.String("job_id", job.ID),
			zap.String("job_type", string(job.Type)),
			zap.String("scan_id", job.ScanID),
		)
		return nil
	default:
		p.logger.Warn("Job queue full, dropping job",
			zap.String("job_id", job.ID),
			zap.String("job_type", string(job.Type)),
		)
		return ErrQueueFull
	}
}

// GetStats returns pool statistics
func (p *Pool) GetStats() PoolStats {
	return PoolStats{
		MaxWorkers:    p.maxWorkers,
		MaxQueue:      p.maxQueue,
		QueueLength:   len(p.jobQueue),
		ActiveWorkers: len(p.workers),
	}
}

// dispatch dispatches jobs to available workers
func (p *Pool) dispatch(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	
	for {
		select {
		case job := <-p.jobQueue:
			// Get an available worker
			select {
			case jobQueue := <-p.workerPool:
				// Dispatch job to worker
				select {
				case jobQueue <- job:
					// Job dispatched successfully
				case <-ctx.Done():
					return
				}
			case <-ctx.Done():
				return
			case <-p.quit:
				return
			}
		case <-ctx.Done():
			return
		case <-p.quit:
			return
		}
	}
}

// Start starts a worker
func (w *Worker) Start(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	
	w.Logger.Debug("Worker started", zap.Int("worker_id", w.ID))
	
	for {
		// Register worker in the worker pool
		w.WorkerPool <- w.JobQueue
		
		select {
		case job := <-w.JobQueue:
			// Process job
			w.Logger.Debug("Processing job",
				zap.Int("worker_id", w.ID),
				zap.String("job_id", job.ID),
				zap.String("job_type", string(job.Type)),
			)
			
			startTime := time.Now()
			err := w.Handler.HandleJob(ctx, job)
			duration := time.Since(startTime)
			
			if err != nil {
				w.Logger.Error("Job failed",
					zap.Int("worker_id", w.ID),
					zap.String("job_id", job.ID),
					zap.String("job_type", string(job.Type)),
					zap.Error(err),
					zap.Duration("duration", duration),
				)
				
				// Retry logic
				if job.Retry < job.MaxRetry {
					job.Retry++
					w.Logger.Info("Retrying job",
						zap.Int("worker_id", w.ID),
						zap.String("job_id", job.ID),
						zap.Int("retry_count", job.Retry),
					)
					// Re-submit job for retry (this is simplified)
				}
			} else {
				w.Logger.Debug("Job completed",
					zap.Int("worker_id", w.ID),
					zap.String("job_id", job.ID),
					zap.String("job_type", string(job.Type)),
					zap.Duration("duration", duration),
				)
			}
			
		case <-w.QuitChan:
			w.Logger.Debug("Worker stopping", zap.Int("worker_id", w.ID))
			return
		case <-ctx.Done():
			w.Logger.Debug("Worker context cancelled", zap.Int("worker_id", w.ID))
			return
		}
	}
}

// PoolStats represents pool statistics
type PoolStats struct {
	MaxWorkers    int `json:"max_workers"`
	MaxQueue      int `json:"max_queue"`  
	QueueLength   int `json:"queue_length"`
	ActiveWorkers int `json:"active_workers"`
}

// Errors
var (
	ErrQueueFull = fmt.Errorf("job queue is full")
)
