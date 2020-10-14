/*
 * Copyright (c) 2019-present Heeus authors
 */

package minibomber

import (
	"crypto/md5"
	"fmt"
	"io"
	"strings"
	"sync/atomic"
	"time"

	"code.cloudfoundry.org/bytefmt"
	"github.com/montanaflynn/stats"
	gc "github.com/untillpro/gochips"
	"github.com/valyala/fasthttp"
)

// Settings keeps the settings
type Settings struct {
	// Print errors to stdout
	//
	// By default set to false
	VerboseErrors bool

	// Print progress
	//
	// By default set to false
	VerboseProgress     bool
	KeyPrefix           string
	MaxConnsPerHost     int
	On503MaxAttempts    uint
	On503DelayMs        uint
	OnRefuseMaxAttempts uint
	OnRefuseDelayMs     uint
	ReadTimeout         time.Duration
	WriteTimeout        time.Duration
	MaxTimeSec          uint
}

var defaultSettings Settings = Settings{
	VerboseErrors:       false,
	VerboseProgress:     false,
	KeyPrefix:           "user",
	On503MaxAttempts:    20,
	On503DelayMs:        0,
	OnRefuseMaxAttempts: 20,
	OnRefuseDelayMs:     0,
	MaxConnsPerHost:     10000,
	ReadTimeout:         10000 * time.Millisecond,
	WriteTimeout:        10000 * time.Millisecond,
	MaxTimeSec:          0,
}

// Results keeps the test results
type Results struct {
	TotalOperations     uint64
	TotalValid          uint64
	TotalTime           time.Duration
	TotalStatus1xx      uint64
	TotalStatus2xx      uint64
	TotalStatus3xx      uint64
	TotalStatus4xx      uint64
	TotalStatus5xx      uint64
	TotalTransferred    uint64
	TotalErrors         uint64
	TotalLatencyNs      int64
	AvgRPS              float64
	MaxRPS              float64
	MinRPS              float64
	AvgThroughputBPS    float64
	AvgLatency          int64
	MinLatency          int64
	MaxLatency          int64
	LatencyPercentile50 int64
	LatencyPercentile75 int64
	LatencyPercentile90 int64
	LatencyPercentile95 int64
	LatencyPercentile99 int64
	FirstError          error
	LastError           error
	TotalRequests       uint64
}

// InitHandler is the initialization handler
type InitHandler func(mb *Minibomber)

// PrepareRequestFunc function prepares http request
type PrepareRequestFunc func(req *FuncInput, request *fasthttp.Request)

// ValidateResponseFunc validates response
type ValidateResponseFunc func(request *fasthttp.Request, response *fasthttp.Response) bool

// TestCase is a single test
type TestCase struct {
	Name             string
	PrepReqFunc      PrepareRequestFunc
	ValidateRespFunc ValidateResponseFunc
	Attackers        int
	Records          uint64
	Operations       uint64
}

// Handlers keeps the optional handlers
type Handlers struct {
	Init InitHandler
}

// FuncInput is the test function input data
type FuncInput struct {
	Key string
}

// FuncOutput is the test function output data
type FuncOutput struct {
	Err       error
	Latency   int64
	Status    int
	RespValid bool
	DataSize  uint64
	Requests  uint64
}

// Minibomber instance
type Minibomber struct {
	testCase TestCase

	cntDone     uint64
	cntRequests uint64
	cntErrs     uint64
	cnt1xx      uint64
	cnt2xx      uint64
	cnt3xx      uint64
	cnt4xx      uint64
	cnt5xx      uint64
	cntLatency  int64
	minLatency  int64
	maxLatency  int64
	maxRPS      float64
	minRPS      float64
	cntDataSize uint64
	cntValid    uint64
	firstErr    error
	lastErr     error
	perc50      int64
	perc75      int64
	perc90      int64
	perc95      int64
	perc99      int64

	keys     []string
	http     fasthttp.Client
	Settings Settings
	Handlers Handlers
}

// NewBomber creates instance of Minibomber
func NewBomber() *Minibomber {
	return &Minibomber{
		Settings: defaultSettings,
		Handlers: Handlers{},
	}
}

func (mb *Minibomber) genKey(sequence uint64) string {
	h := md5.New()
	io.WriteString(h, fmt.Sprintf("%.10d", sequence))
	md5 := h.Sum(nil)
	var buf strings.Builder
	for i := 0; i < 16; i++ {
		buf.WriteByte(48 + md5[i]%10)
	}
	return mb.Settings.KeyPrefix + buf.String()
}

func (mb *Minibomber) prepare() {
	if mb.Settings.VerboseProgress {
		gc.Doing(fmt.Sprintf("Preparing %d keys", mb.testCase.Records))
	}
	var i uint64
	mb.keys = make([]string, mb.testCase.Records)
	for i = 0; i < mb.testCase.Records; i++ {
		mb.keys[i] = mb.genKey(i)
	}
}

func (mb *Minibomber) reset() {
	mb.http = fasthttp.Client{
		MaxConnsPerHost: mb.Settings.MaxConnsPerHost,
		ReadTimeout:     mb.Settings.ReadTimeout,
		WriteTimeout:    mb.Settings.WriteTimeout,
	}
	mb.cntDone = 0
	mb.cntRequests = 0
	mb.cntDataSize = 0
	mb.maxLatency = -1
	mb.minLatency = -1
	mb.cntLatency = 0
	mb.cnt1xx = 0
	mb.cnt2xx = 0
	mb.cnt3xx = 0
	mb.cnt4xx = 0
	mb.cnt5xx = 0
	mb.firstErr = nil
	mb.lastErr = nil
	mb.cntErrs = 0
	mb.cntValid = 0
	mb.maxRPS = 0
	mb.minRPS = 0
	if mb.Handlers.Init != nil {
		mb.Handlers.Init(mb)
	}
}

func (mb *Minibomber) handleThread(input chan FuncInput, output chan FuncOutput, finished chan bool) {
	refuseMaxAttempts := mb.Settings.OnRefuseMaxAttempts
	refuseSleepMs := mb.Settings.OnRefuseDelayMs
	unavailMaxAttempts := mb.Settings.On503MaxAttempts
	unvailSleepMs := mb.Settings.On503DelayMs
	reqf := mb.testCase.PrepReqFunc
	respf := mb.testCase.ValidateRespFunc
	var size uint64 = 0
	var status int = 0
	var valid bool = true
	var attempts uint
	var err error

	httpreq := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(httpreq)
	httpresp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(httpresp)

	for {
		req, more := <-input
		if more {
			t0 := time.Now()

			reqf(&req, httpreq)

			attempts = 0
			size = 0
			err = nil
			for {
				err = mb.http.Do(httpreq, httpresp)
				attempts++
				if err != nil && refuseMaxAttempts > 0 && strings.Contains(err.Error(), "refused") && attempts <= refuseMaxAttempts {
					if refuseSleepMs > 0 {
						time.Sleep(time.Duration(refuseSleepMs) * time.Millisecond)
					}
					continue
				}
				if err != nil {
					break
				}
				size += uint64(len(httpreq.Body()) + len(httpresp.Body()))
				if httpresp.StatusCode() == fasthttp.StatusServiceUnavailable && attempts <= unavailMaxAttempts {
					if unvailSleepMs > 0 {
						time.Sleep(time.Duration(unvailSleepMs) * time.Millisecond)
					}
					continue
				}
				status = httpresp.StatusCode()
				break
			}

			if respf != nil {
				valid = respf(httpreq, httpresp)
			}

			output <- FuncOutput{
				Latency:   time.Now().Sub(t0).Nanoseconds(),
				Err:       err,
				DataSize:  size,
				Status:    status,
				RespValid: valid,
				Requests:  uint64(attempts),
			}
		} else {
			finished <- true
			return
		}
	}
}

func (mb *Minibomber) collectStat(stop chan bool, finished chan bool) {
	tickerch := time.NewTicker(1 * time.Second).C
	var lastDone uint64
	t0 := time.Now()
	for {
		select {
		case now := <-tickerch:
			done := atomic.LoadUint64(&mb.cntDone)
			s100 := atomic.LoadUint64(&mb.cnt1xx)
			s200 := atomic.LoadUint64(&mb.cnt2xx)
			s300 := atomic.LoadUint64(&mb.cnt3xx)
			s400 := atomic.LoadUint64(&mb.cnt4xx)
			s500 := atomic.LoadUint64(&mb.cnt5xx)
			errs := atomic.LoadUint64(&mb.cntErrs)
			span := now.Sub(t0)
			rps := float64(done-lastDone) / span.Seconds()

			if rps > mb.maxRPS {
				mb.maxRPS = rps
			}

			if rps < mb.minRPS || mb.minRPS == 0 {
				mb.minRPS = rps
			}

			if mb.Settings.VerboseProgress {
				gc.Doing(fmt.Sprintf("%d%%: 2xx %d, others %d, errors %d, rps: %.1f", done*100/mb.testCase.Operations, s200, s100+s300+s400+s500, errs, rps))
			}
			t0 = now
			lastDone = done
		case <-stop:
			finished <- true
			return
		}
	}
}

func intvlToString(intvl int64) string {
	d := time.Duration(intvl)
	if d.Hours() >= 10 {
		return fmt.Sprintf("%.1fh", d.Hours())
	} else if d.Minutes() >= 10 {
		return fmt.Sprintf("%.1fm", d.Minutes())
	} else if d.Seconds() >= 10 {
		return fmt.Sprintf("%.1fs", d.Seconds())
	} else if d.Milliseconds() >= 10 {
		return fmt.Sprintf("%.dms", d.Milliseconds())
	} else if d.Microseconds() >= 10 {
		return fmt.Sprintf("%.dus", d.Microseconds())
	} else if d.Nanoseconds() > 0 {
		return fmt.Sprintf("%dns", d.Nanoseconds())
	}
	return "0"
}

func (mb *Minibomber) fetchResults(output chan FuncOutput, finished chan bool) {
	latencies := make([]float64, mb.testCase.Operations)
	var i uint64 = 0
	for {
		res, more := <-output
		if more {
			atomic.AddUint64(&mb.cntDone, 1)
			if res.Err != nil {
				if mb.Settings.VerboseErrors {
					gc.Info("Error: " + res.Err.Error())
				}
				atomic.AddUint64(&mb.cntErrs, 1)
				if mb.firstErr == nil {
					mb.firstErr = res.Err
				}
				mb.lastErr = res.Err
			} else {
				var c int = res.Status / 100
				if c == 1 {
					atomic.AddUint64(&mb.cnt1xx, 1)
				} else if c == 2 {
					atomic.AddUint64(&mb.cnt2xx, 1)
				} else if c == 3 {
					atomic.AddUint64(&mb.cnt3xx, 1)
				} else if c == 4 {
					atomic.AddUint64(&mb.cnt4xx, 1)
				} else if c == 5 {
					atomic.AddUint64(&mb.cnt5xx, 1)
				}
				if res.RespValid {
					atomic.AddUint64(&mb.cntValid, 1)
				}
			}
			latencies[i] = float64(res.Latency)
			atomic.AddInt64(&mb.cntLatency, res.Latency)
			atomic.AddUint64(&mb.cntDataSize, res.DataSize)
			atomic.AddUint64(&mb.cntRequests, res.Requests)
			if mb.maxLatency == -1 || res.Latency > mb.maxLatency {
				mb.maxLatency = res.Latency
			}
			if mb.minLatency == -1 || res.Latency < mb.minLatency {
				mb.minLatency = res.Latency
			}
			i++
		} else {
			break
		}
	}
	if i < mb.testCase.Operations {
		latencies = append([]float64(nil), latencies[:i]...)
	}
	mb.perc50 = percentile(latencies, 50)
	mb.perc75 = percentile(latencies, 75)
	mb.perc90 = percentile(latencies, 90)
	mb.perc95 = percentile(latencies, 95)
	mb.perc99 = percentile(latencies, 99)

	finished <- true
}

// Run runs the bomber
func (mb *Minibomber) Run(testcase TestCase) Results {
	mb.testCase = testcase
	mb.prepare()
	if mb.Settings.VerboseProgress {
		gc.Doing("Starting test")
	}
	chInput := make(chan FuncInput)
	chOutput := make(chan FuncOutput)
	finishedThreads := make(chan bool)
	stopStat := make(chan bool)
	mb.reset()

	for t := 0; t < mb.testCase.Attackers; t++ {
		go mb.handleThread(chInput, chOutput, finishedThreads)
	}
	if mb.Settings.VerboseProgress {
		gc.Doing(fmt.Sprintf("Running test-case: %d attackers, %d records", mb.testCase.Attackers, mb.testCase.Records))
	}
	//go mb.sendKeys(chInput)
	go mb.collectStat(stopStat, finishedThreads)
	go mb.fetchResults(chOutput, finishedThreads)

	t0 := time.Now()
	var i, keyIndex uint64
	var timeoutSec uint = mb.Settings.MaxTimeSec

	for i = 0; i < mb.testCase.Operations; i++ {
		if timeoutSec > 0 {
			if i%50 == 49 {
				t1 := time.Now()
				if t1.Sub(t0).Seconds() >= float64(timeoutSec) {
					break
				}
			}
		}
		keyIndex = i % mb.testCase.Records
		chInput <- FuncInput{
			Key: mb.keys[keyIndex],
		}
	}

	close(chInput)
	for t := 0; t < mb.testCase.Attackers; t++ {
		<-finishedThreads
	}

	close(chOutput)
	<-finishedThreads // fetchResults

	stopStat <- true
	<-finishedThreads // showStat

	results := Results{}
	results.TotalTime = time.Now().Sub(t0)
	results.AvgRPS = float64(mb.cntDone) / results.TotalTime.Seconds()
	results.MaxRPS = mb.maxRPS
	results.MinRPS = mb.minRPS
	results.TotalTransferred = mb.cntDataSize
	results.TotalLatencyNs = mb.cntLatency
	results.AvgThroughputBPS = float64(mb.cntDataSize) / results.TotalTime.Seconds()
	results.MinLatency = mb.minLatency
	results.MaxLatency = mb.maxLatency
	results.AvgLatency = mb.cntLatency / int64(mb.cntDone)
	results.LatencyPercentile50 = mb.perc50
	results.LatencyPercentile75 = mb.perc75
	results.LatencyPercentile90 = mb.perc90
	results.LatencyPercentile95 = mb.perc95
	results.LatencyPercentile99 = mb.perc99
	results.FirstError = mb.firstErr
	results.LastError = mb.lastErr
	results.TotalStatus1xx = mb.cnt1xx
	results.TotalStatus2xx = mb.cnt2xx
	results.TotalStatus3xx = mb.cnt3xx
	results.TotalStatus4xx = mb.cnt4xx
	results.TotalStatus5xx = mb.cnt5xx
	results.TotalOperations = mb.cntDone
	results.TotalValid = mb.cntValid
	results.TotalErrors = mb.cntErrs
	results.TotalRequests = mb.cntRequests

	if mb.Settings.VerboseProgress {
		gc.Info(results.String())
	}

	return results

}

func percentile(data []float64, percent int) int64 {
	p, err := stats.Percentile(data, float64(percent))
	gc.ExitIfError(err)
	return int64(p)
}

func (r *Results) String() string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("%-16s%d operations in %.1f seconds\n", "Overall", r.TotalOperations, r.TotalTime.Seconds()))
	b.WriteString(fmt.Sprintf("%-16s%-12s%-12s%-12s\n", "Statistics", "Avg", "Min", "Max"))
	b.WriteString(fmt.Sprintf("%-16s%-12.1f%-12.1f%-12.1f\n", "Req/sec", r.AvgRPS, r.MinRPS, r.MaxRPS))

	var minl, maxl string
	if r.MinLatency == -1 {
		minl = ""
	} else {
		minl = intvlToString(r.MinLatency)
	}
	if r.MaxLatency == -1 {
		maxl = ""
	} else {
		maxl = intvlToString(r.MaxLatency)
	}

	b.WriteString(fmt.Sprintf("%-16s%-12s%-12s%-12s\n", "Latency", intvlToString(r.AvgLatency), minl, maxl))
	b.WriteString(fmt.Sprintf("Latency Distribution\n"))
	b.WriteString(fmt.Sprintf("      50%%    %s\n", intvlToString(r.LatencyPercentile50)))
	b.WriteString(fmt.Sprintf("      75%%    %s\n", intvlToString(r.LatencyPercentile75)))
	b.WriteString(fmt.Sprintf("      90%%    %s\n", intvlToString(r.LatencyPercentile90)))
	b.WriteString(fmt.Sprintf("      95%%    %s\n", intvlToString(r.LatencyPercentile95)))
	b.WriteString(fmt.Sprintf("      99%%    %s\n", intvlToString(r.LatencyPercentile99)))
	b.WriteString(fmt.Sprintf("%-16s%s/s\n", "Throughput", bytefmt.ByteSize(uint64(r.AvgThroughputBPS))))
	b.WriteString(fmt.Sprintf("%-16s%s\n", "Transferred", bytefmt.ByteSize(r.TotalTransferred)))
	b.WriteString(fmt.Sprintf("%-16s%d\n", "Requests sent", r.TotalRequests))

	if r.TotalValid < r.TotalOperations {
		b.WriteString(fmt.Sprintf("%-16s%d\n", "INVALID RESP", r.TotalOperations-r.TotalValid))
	}
	if r.TotalErrors > 0 {
		b.WriteString(fmt.Sprintf("%-16s%d\n", "ERRORS", r.TotalErrors))
		if r.FirstError.Error() != r.LastError.Error() {
			b.WriteString(fmt.Sprintf("%-16s%s\n", "First err", r.FirstError.Error()))
			b.WriteString(fmt.Sprintf("%-16s%s\n", "Last err", r.LastError.Error()))
		} else {
			b.WriteString(fmt.Sprintf("%-16s%s\n", "Error", r.LastError.Error()))
		}
	}
	b.WriteString(fmt.Sprintf("%-16s1xx - %d, 2xx - %d, 3xx - %d, 4xx - %d, 5xx - %d\n", "HTTP codes", r.TotalStatus1xx, r.TotalStatus2xx, r.TotalStatus3xx, r.TotalStatus4xx, r.TotalStatus5xx))

	return b.String()
}
