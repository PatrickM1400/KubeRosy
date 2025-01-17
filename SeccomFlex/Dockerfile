FROM amd64/golang:latest    

WORKDIR /usr/daemon

COPY . .

RUN go build .

ENTRYPOINT ["./core"]