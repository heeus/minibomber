package minibomber

import (
	"fmt"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"
)

func Test_IntvlToString(t *testing.T) {
	assert.Equal(t, "0", intvlToString(0))
	assert.Equal(t, "123ns", intvlToString(123))
	assert.Equal(t, "9123ns", intvlToString(9123))
	assert.Equal(t, "12us", intvlToString(12123))
	assert.Equal(t, "123us", intvlToString(123123))
	assert.Equal(t, "3123us", intvlToString(3123123))
	assert.Equal(t, "13ms", intvlToString(13123123))
	assert.Equal(t, "131ms", intvlToString(131231233))
	assert.Equal(t, "1131ms", intvlToString(1131231233))
	assert.Equal(t, "9999ms", intvlToString(9999999999))
	assert.Equal(t, "10.0s", intvlToString(10000000000))
	assert.Equal(t, "66.2s", intvlToString(66170000000))
	assert.Equal(t, "599.9s", intvlToString(599900000000))
	assert.Equal(t, "10.0m", intvlToString(600000000000))
	assert.Equal(t, "60.0m", intvlToString(3600000000000))
	assert.Equal(t, "60.2m", intvlToString(3610000000000))
	assert.Equal(t, "120.0m", intvlToString(7200000000000))
	assert.Equal(t, "10.0h", intvlToString(36000000000000))
	assert.Equal(t, "100.0h", intvlToString(360000000000000))
}

func Test_GenKey(t *testing.T) {
	mb := NewBomber()
	assert.Equal(t, "user5873743543233747", mb.genKey(1))
	assert.Equal(t, "user9947326630571403", mb.genKey(2))
}

func fastHTTPHandler(ctx *fasthttp.RequestCtx) {
	time.Sleep(1 * time.Millisecond)
	fmt.Fprintf(ctx, "ok")
}

func server(s *fasthttp.Server) {
	if err := s.ListenAndServe(":10200"); err != nil {
		log.Fatalf("error in ListenAndServe: %s", err)
	}
}

func Test_Results(t *testing.T) {
	s := &fasthttp.Server{
		Handler: fastHTTPHandler,
	}
	go server(s)
	mb := NewBomber()
	mb.Settings.VerboseProgress = true
	res := mb.Run(TestCase{
		Attackers:  2,
		Operations: 10,
		Records:    4,
		PrepReqFunc: func(req *FuncInput, request *fasthttp.Request) {
			request.SetRequestURI("http://127.0.0.1:10200")
			request.Header.SetMethodBytes([]byte("GET"))
		},
		ValidateRespFunc: func(request *fasthttp.Request, response *fasthttp.Response) bool {
			return strings.Index(string(response.Body()), "ok") >= 0
		},
	})

	assert.Equal(t, uint64(10), res.TotalOperations)
	assert.Equal(t, uint64(0), res.TotalErrors)
	assert.True(t, res.AvgLatency > 1000000)
	assert.True(t, res.TotalLatencyNs > 10*1000000)
	assert.True(t, res.TotalLatencyNs < 100*1000000)
	assert.Equal(t, nil, res.FirstError)
	assert.Equal(t, nil, res.LastError)
	assert.Equal(t, uint64(0), res.TotalStatus1xx)
	assert.Equal(t, uint64(10), res.TotalStatus2xx)
	assert.Equal(t, uint64(0), res.TotalStatus3xx)
	assert.Equal(t, uint64(0), res.TotalStatus4xx)
	assert.Equal(t, uint64(0), res.TotalStatus5xx)

	s.Shutdown()

}
