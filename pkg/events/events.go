package events

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/nats-io/nats.go"

	pkgsvctls "vecta-kms/pkg/svctls"
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
	// Internal mTLS to NATS (docs/SECURITY/INTERNAL_TLS.md), and keep
	// retrying if NATS isn't up yet rather than running without audit.
	opts = append(opts, nats.RetryOnFailedConnect(true))
	if id := pkgsvctls.Current(); id != nil {
		opts = append(opts, nats.Secure(id.ClientTLSConfigFor(natsHost(url))))
	}
	return nats.Connect(url, opts...)
}

func natsHost(url string) string {
	u := url
	if i := strings.Index(u, "://"); i >= 0 {
		u = u[i+3:]
	}
	if i := strings.LastIndex(u, "@"); i >= 0 {
		u = u[i+1:]
	}
	if i := strings.IndexAny(u, ":/,"); i >= 0 {
		u = u[:i]
	}
	return u
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
