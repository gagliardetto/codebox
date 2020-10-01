**Summary**: Codebox is a **graphical tool** that helps to **create taint-tracking models** for **Go** functions/methods/interfaces; you specify the **taint logic** in a graphical (**web**) interface, and it **generates CodeQL taint-tracking models** along with Go scenario **test cases** for those models.

![codebox_screenshot](https://user-images.githubusercontent.com/15271561/86345187-e2bc5900-bc63-11ea-95e5-5f5e63e7040f.png)

# Example

The `codebox` tool was created to expand the **taint-tracking models** of [codeql-go](https://github.com/github/codeql-go) (the official CodeQL extractor and libraries for Go.)

You can find below all the models and tests that were generated by `codebox` and then merged into the [codeql-go](https://github.com/github/codeql-go) repo:
 - Taint-tracking models: https://github.com/github/codeql-go/tree/main/ql/src/semmle/go/frameworks/stdlib
 - Tests: https://github.com/github/codeql-go/tree/main/ql/test/library-tests/semmle/go/frameworks/StdlibTaintFlow
 - Imports: https://github.com/github/codeql-go/blob/main/ql/src/semmle/go/frameworks/Stdlib.qll#L6-L65
 - More about the goal: https://github.com/github/securitylab/issues/187

NOTE: The `codebox` tool and its author have no affiliation with GitHub/Semmle.

# How it works

```bash
# - go get
go get github.com/gagliardetto/codebox

# - Enter the codebox folder:
cd $GOPATH/src/github.com/gagliardetto/codebox

# - Compile and install the binary:
make

# - Spin up the graphical tool http server for e.g. the "io" package.
# NOTE: you still need to be inside $GOPATH/src/github.com/gagliardetto/codebox
# NOTE: the --pkg flag must be the absolute path to the package.
# NOTE: there might be some issues with some packages or modules.
# NOTE: the --out-dir flag is the folder where all the generated files will go.
codebox --out-dir=./generated/compressed --pkg=/usr/local/go/src/io --stub --http

# - Open the UI in the browser:
chrome http://127.0.0.1:8080/

# - Now that you see the UI in the browser, complete the taint-tracking logic
# and when you're done, close the server program you started in the terminal
# with a CTRL-C.
# You will find the generated codeql and golang files inside ./generated/compressed

# NOTE: if you only want to regenerate the code without starting the server,
# then you need to remove the --http flag:
codebox --out-dir=./generated/compressed --pkg=/usr/local/go/src/io --stub
```

# Helpful commands for batch processing

```bash
# Move all files from child directories to parent directory:
# find . -mindepth 2 -type f -name "*.go" -print -exec mv {} . \;
# find . -mindepth 2 -type f -name "*.qll" -print -exec mv {} . \;
 find . -mindepth 2 -type f -print -exec mv {} . \;

#for f in *.qll; do printf '%s\n' "${f%.qll}TaintTracking.qll"; done

rename 's/\.qll$/TaintTracking.qll/' *.qll

# format a codeql file:
codeql query format -qq -i file.qll

# format all codeql files:

 echo ~/.config/Code/User/globalStorage/github.vscode-codeql/distribution*/codeql/codeql
 find . -type f -name "*.ql" -or -name "*.qll" -exec ~/.config/Code/User/globalStorage/github.vscode-codeql/distribution12/codeql/codeql query format -qq -i {} ';' -print

 find . -type f -name "*.ql" -or -name "*.qll" | while read cqlFile; do echo $cqlFile && codeql query format -qq -i $cqlFile; done


```
