module github.com/cyrill-k/trustflex

go 1.13

replace github.com/miekg/dns => /home/cyrill/go/src/github.com/cyrill-k/dns

replace github.com/google/trillian => /home/cyrill/go/src/github.com/cyrill-k/trillian

require (
	github.com/golang/protobuf v1.3.3
	github.com/google/certificate-transparency-go v1.1.0
	github.com/google/trillian v1.3.3
	github.com/miekg/dns v1.1.27
	golang.org/x/crypto v0.0.0-20191206172530-e9b2fee46413 // indirect
	golang.org/x/net v0.0.0-20191209160850-c0dbc17a3553
	google.golang.org/api v0.15.0 // indirect
	google.golang.org/grpc v1.26.0
)
