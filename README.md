# preparation

```bash
# - Create stdlib folder
cd ~/vscode-codeql-starter/codeql-go/ql/src/semmle/go/frameworks
mkdir stdlib
# - Put the qll files inside stdlib (e.g. stdlib/SomeLibrary.qll)
# - The imports will look like this:
# import semmle.go.frameworks.stdlib.SomeLibrary
# - Add import to ~/vscode-codeql-starter/codeql-go/ql/src/semmle/go/frameworks/stdlib/ImportAll.qll
# so to be able to import them all with a single line (by `import semmle.go.frameworks.stdlib.ImportAll`)

# - Tests:
cd ~/vscode-codeql-starter/codeql-go/ql/test/library-tests/semmle/go/frameworks
mkdir StdlibTaintFlow
# - Either make a folder for each std library where you put the go file and the query,
# OR
# - add the go files and the .expected files to this same folder, and use just one query file.


# Run test
codeql test run \
	--search-path=/home/withparty/vscode-codeql-starter/ \
	/home/withparty/vscode-codeql-starter/codeql-go/ql/test/library-tests/semmle/go/frameworks/StdlibTaintFlow

```


```bash
# move all files from child directories to parent directory:
# find . -mindepth 2 -type f -name "*.qll" -print -exec mv {} . \;
 find . -mindepth 2 -type f -print -exec mv {} . \;

#for f in *.qll; do printf '%s\n' "${f%.qll}TaintTracking.qll"; done

rename 's/\.qll$/TaintTracking.qll/' *.qll

# format a codeql file:
codeql query format -qq -i file.qll

# format all codeql files:

 echo /home/withparty/.config/Code/User/globalStorage/github.vscode-codeql/distribution*/codeql/codeql
 find . -type f -name "*.ql" -or -name "*.qll" -exec /home/withparty/.config/Code/User/globalStorage/github.vscode-codeql/distribution12/codeql/codeql query format -qq -i {} ';' -print

 find . -type f -name "*.ql" -or -name "*.qll" | while read cqlFile; do echo $cqlFile && codeql query format -qq -i $cqlFile; done


```


---

# standard library

### place where to put miscelaneous stuff
import semmle.go.frameworks.stdlib.Misc
OR
import semmle.go.frameworks.stdlib.Stdlib

### taint-tracking for a package of stdlib
import semmle.go.frameworks.stdlib.IoTaintTracking

### in case you need a file for other structures for a specific package of std lib:
import semmle.go.frameworks.stdlib.Io


# other libraries

### taint-tracking for package
import semmle.go.frameworks.gin.GinTaintTracking

#### taint-tracking for another gin package
import semmle.go.frameworks.gin.GinContribTaintTracking

### misc stuff of gin package
import semmle.go.frameworks.gin.Gin

### misc stuff of gin contrib package (could go to semmle.go.frameworks.gin.Gin if not a lot)
import semmle.go.frameworks.gin.GinContrib


