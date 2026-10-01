package score_test

import (
	"testing"
	"time"

	"github.com/gl1tch0x1/YourWAFSucks/internal/calibrate"
	"github.com/gl1tch0x1/YourWAFSucks/internal/httpclient"
	"github.com/gl1tch0x1/YourWAFSucks/internal/score"
)

func TestScoreStatusTransition(t *testing.T) {
	cal := &calibrate.Result{
		BaselineStatus: 403,
		BaselineSize:   500,
		BaselineTime:   100 * time.Millisecond,
		BaselineBody:   []byte("403 forbidden"),
	}
	resp := &httpclient.Response{
		Status: 200,
		Body:   []byte("welcome to admin dashboard"),
		Time:   150 * time.Millisecond,
	}
	r := score.Compute(resp, cal)
	if !r.Interesting {
		t.Fatalf("expected interesting, got %+v", r)
	}
	if r.Score < 50 {
		t.Fatalf("expected score >= 50, got %d", r.Score)
	}
}

func TestScoreIdenticalResponse(t *testing.T) {
	body := []byte("403 forbidden")
	cal := &calibrate.Result{
		BaselineStatus: 403,
		BaselineSize:   len(body),
		BaselineBody:   body,
	}
	resp := &httpclient.Response{
		Status: 403,
		Body:   body,
	}
	r := score.Compute(resp, cal)
	if r.Interesting {
		t.Fatalf("expected not interesting, got %+v", r)
	}
}
