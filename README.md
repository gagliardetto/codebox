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
mkdir stdlib
# - Either make a folder for each std library where you put the go file and the query,
# OR
# - add the go files and the .expected files to this same folder, and use just one query file.
```
