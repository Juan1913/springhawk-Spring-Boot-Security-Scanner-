package engine

import (
	"context"
	"sync"
)

type Job[T any] struct {
	ID      string
	Payload T
}

type Result[T any, R any] struct {
	Job   Job[T]
	Value R
	Err   error
}

type WorkerPool[T any, R any] struct {
	workers   int
	jobs      chan Job[T]
	results   chan Result[T, R]
	wg        sync.WaitGroup
	processor func(ctx context.Context, job Job[T]) (R, error)
}

func NewWorkerPool[T any, R any](
	workers, bufferSize int,
	processor func(ctx context.Context, job Job[T]) (R, error),
) *WorkerPool[T, R] {
	if workers < 1 {
		workers = 1
	}
	return &WorkerPool[T, R]{
		workers:   workers,
		jobs:      make(chan Job[T], bufferSize),
		results:   make(chan Result[T, R], bufferSize),
		processor: processor,
	}
}

func (p *WorkerPool[T, R]) Start(ctx context.Context) {
	for i := 0; i < p.workers; i++ {
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			for job := range p.jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}
				val, err := p.processor(ctx, job)
				p.results <- Result[T, R]{Job: job, Value: val, Err: err}
			}
		}()
	}
}

func (p *WorkerPool[T, R]) Submit(job Job[T]) {
	p.jobs <- job
}

func (p *WorkerPool[T, R]) Close() {
	close(p.jobs)
}

func (p *WorkerPool[T, R]) Wait() {
	p.wg.Wait()
	close(p.results)
}

func (p *WorkerPool[T, R]) Results() <-chan Result[T, R] {
	return p.results
}
