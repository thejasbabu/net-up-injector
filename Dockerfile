FROM golang:1.13-alpine as builder
RUN mkdir -p /net-up-injector
COPY . /net-up-injector
WORKDIR /net-up-injector
RUN go clean && go build

FROM alpine
COPY --from=builder /net-up-injector/net-up-injector ./net-up-injector
CMD ./net-up-injector