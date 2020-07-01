#### Graphical tool to taint-track Go functions/methods/interfaces and generate CodeQL along with Go scenario test cases.

![tool_screenshot](https://user-images.githubusercontent.com/15271561/85956661-f92a9200-b98f-11ea-9ddd-d36047b262f8.png)

# How it works

```bash
# - Enter the codebox folder:
cd ~/go/src/github.com/gagliardetto/codebox

# - Compile the binary:
make

# - Spin up the graphical tool http server for e.g. the "io" package.
# NOTE: the --pkg flag must be the absolute path to the package.
# NOTE: there might be some issues with some packages or modules.
# NOTE: the --out-dir flag is the folder where all the generated files will go.
codebox --out-dir=./generated/compressed --pkg=/usr/local/go/src/io --stub --http

# - Open the UI in the browser:
chrome http://127.0.0.1:8080/

# - Now that you see the UI in the browser, complete the taint-tracking logic
# and when you're done, close the server program you started in the terminal
# with a CTRL-C.

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
