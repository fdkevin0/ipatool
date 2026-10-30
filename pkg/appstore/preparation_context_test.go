package appstore

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/majd/ipatool/v2/pkg/http"
	"go.uber.org/mock/gomock"
)

func TestBagPreparationCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	client := http.NewMockClient[bagResult](gomock.NewController(t))
	client.EXPECT().Send(gomock.Any()).DoAndReturn(func(req http.Request) (http.Result[bagResult], error) {
		if req.Context != ctx {
			t.Fatal("Store preparation lost the login context and deadline")
		}

		cancel()
		select {
		case <-req.Context.Done():
			return http.Result[bagResult]{}, req.Context.Err()
		case <-time.After(time.Second):
			t.Fatal("Store request did not stop on cancellation")

			return http.Result[bagResult]{}, nil
		}
	})

	store := &appstore{bagClient: client}
	if _, err := store.bag(ctx, "AABBCCDDEEFF"); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation during Store preparation, got %v", err)
	}
}

func TestCanceledBagPreparationSkipsRequest(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	store := &appstore{bagClient: http.NewMockClient[bagResult](gomock.NewController(t))}
	if _, err := store.bag(ctx, "AABBCCDDEEFF"); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation before Store preparation, got %v", err)
	}
}

func TestSignerFactoryPreservesCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// Cancellation must reach NewSigner before config checks or runtime loading.
	signer, err := frameworkActionSignerFactory(nil)(ctx, SAPConfig{}, nil)
	if signer != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("signer factory lost cancellation: signer=%v, err=%v", signer, err)
	}
}
