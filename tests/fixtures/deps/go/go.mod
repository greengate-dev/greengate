module example.com/fixture

go 1.22

require (
	github.com/gin-gonic/gin v1.9.0
	golang.org/x/net v0.17.0
)

require (
	github.com/bytedance/sonic v1.9.1 // indirect
	golang.org/x/text v0.13.0 // indirect
)

replace golang.org/x/net => golang.org/x/net v0.23.0

replace example.com/local => ../local
