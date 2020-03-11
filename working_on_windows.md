# Original errors when building
- cd cmd/gobgpd
- go build
 - or in Linux "GOOS=windows go build"
 - same errors come up there
- 
```
# github.com/osrg/gobgp/pkg/server
..\..\pkg\server\sockopt.go:31:9: undefined: setListenTcpTTLSockopt
..\..\pkg\server\util.go:87:12: undefined: syscall.SetsockoptString
..\..\pkg\server\util.go:99:37: cannot use int(s) (type int) as type syscall.Handle in argument to syscall.SetsockoptInt
```

- Initial investigate indicates there are some functions in syscall that are present in Linux but not in Windows
    - Compare: 
     - https://golang.org/pkg/syscall/?GOOS=linux
     - https://golang.org/pkg/syscall/?GOOS=windows
- Each supported platform has its own sockopt_<platform>.go file that is selected to be used when compiling
 - I'm going to make one for Windows and have it be used when compiling for Windows, and "fix" functions to use primitives that are in Windows
 - I noticed BSD seems to have a similar problem as Windows, so I'm going to start by copying that and renaming it to sockopt_windows.go
 