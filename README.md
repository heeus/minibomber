# Minibomber - HTTP benchmarking library for golang

## Usage
```go
mb := NewBomber()
mb.Settings.VerboseProgress = true
res := mb.Run(TestCase{
    Attackers:  400,
    Operations: 100000,
    Records:    10000,
    PrepReqFunc: func(req *FuncInput, request *fasthttp.Request) {
        request.SetRequestURI("http://127.0.0.1:10200")
        request.Header.SetMethodBytes([]byte("GET"))
    },
    ValidateRespFunc: func(request *fasthttp.Request, response *fasthttp.Response) bool {
        return strings.Index(string(response.Body()), "ok") >= 0
    },
})
fmt.Printf(res.String())

```

Output:
```
Overall         100000 operations in 1.4 seconds
Statistics      Avg         Min         Max
Req/sec         70060.8     67201.3     67201.3
Latency         4988us      1948us      648ms
Throughput      18.3M/s
Transferred     26.1M
HTTP codes      1xx - 0, 2xx - 100000, 3xx - 0, 4xx - 0, 5xx - 0
```