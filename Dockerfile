FROM golang:1.16-buster as build

WORKDIR /go/src/github.com/calebdoxsey/google-jwt-access-token
ADD go.mod go.sum ./
RUN go mod download

ADD *.go ./
RUN go build -o /go/bin/app

# Now copy it into our base image.
FROM gcr.io/distroless/base-debian10
COPY --from=build /go/bin/app /
CMD ["/app"]