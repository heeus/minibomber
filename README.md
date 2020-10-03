# Minibomber - HTTP benchmarking library for golang

## Usage
```go
mb := NewBomber()
mb.Settings.VerboseProgress = true
res := mb.Run(TestCase{
    Attackers:  2,
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
assert.Equal(t, uint64(10), res.TotalStatus2xx)
```