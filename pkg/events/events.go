package events

import (
	"context"
	"errors"
	"time"

	"github.com/nats-io/nats.go"
)

type Publisher struct {
	js         nats.JetStreamContext
	retries    int
	deadLetter string
}

func Connect(url string, clientName string, logf func(string, ...interface{})) (*nats.Conn, error) {
	opts := []nats.Option{
		nats.Name(clientName),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(2 * time.Second),
		nats.Timeout(5 * time.Second),
		nats.PingInterval(20 * time.Second),
		nats.MaxPingsOutstanding(3),
		nats.ReconnectBufSize(8 * 1024 * 1024),
	}
	if logf != nil {
		opts = append(opts,
			nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
				if err != nil {
					logf("nats disconnected: %v", err)
					return
				}
				logf("nats disconnected")
			}),
			nats.ReconnectHandler(func(nc *nats.Conn) {
				logf("nats reconnected: %s", nc.ConnectedUrl())
			}),
			nats.ClosedHandler(func(_ *nats.Conn) {
				logf("nats connection closed")
			}),
			nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
				if err != nil {
					logf("nats async error: %v", err)
				}
			}),
		)
	}
	return nats.Connect(url, opts...)
}

func NewPublisher(js nats.JetStreamContext, retries int, deadLetter string) *Publisher {
	if retries <= 0 {
		retries = 3
	}
	return &Publisher{js: js, retries: retries, deadLetter: deadLetter}
}

func (p *Publisher) Publish(ctx context.Context, subject string, payload []byte) error {
	if ctx == nil {
		ctx = context.Background()
	}
	// Prevent request handlers from hanging indefinitely when JetStream is slow/unavailable.
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 1500*time.Millisecond)
		defer cancel()
	}

	var err error
	for i := 0; i < p.retries; i++ {
		if deadlineErr := ctx.Err(); deadlineErr != nil {
			return deadlineErr
		}
		_, err = p.js.PublishMsg(&nats.Msg{
			Subject: subject,
			Data:    payload,
		}, nats.Context(ctx))
		if err == nil {
			return nil
		}
		wait := time.Duration(i+1) * 100 * time.Millisecond
		timer := time.NewTimer(wait)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		}
	}
	if p.deadLetter != "" {
		_, _ = p.js.PublishMsg(&nats.Msg{
			Subject: p.deadLetter,
			Data:    payload,
			Header:  nats.Header{"x-original-subject": []string{subject}},
		}, nats.Context(ctx))
	}
	return err
}

type Subscriber struct {
	js nats.JetStreamContext
}

func NewSubscriber(js nats.JetStreamContext) *Subscriber {
	return &Subscriber{js: js}
}

func (s *Subscriber) SubscribeDurable(subject string, durable string, handler nats.MsgHandler) (*nats.Subscription, error) {
	if durable == "" {
		return nil, errors.New("durable consumer name is required")
	}
	return s.js.Subscribe(subject, handler, nats.Durable(durable), nats.ManualAck())
}
