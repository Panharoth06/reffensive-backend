package queue

import "github.com/hibiken/asynq"

func NewWorkerServer(redisAddr string, concurrency int) *asynq.Server {
	if concurrency <= 0 {
		concurrency = 2
	}
	return asynq.NewServer(redisOpt(redisAddr), asynq.Config{
		Concurrency: concurrency,
		Queues: map[string]int{
			"sonarqube": 10,
			"default":   1,
		},
	})
}
