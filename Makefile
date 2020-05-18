.DEFAULT_GOAL := run
run:
	cd ${GOPATH}/src/github.com/gagliardetto/codebox; (go run main.go --pkg=$(src_pkg)); (sleep 2; chromium "http://127.0.0.1:8080/")
