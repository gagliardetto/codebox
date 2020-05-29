cd $GOPATH/src && for dir in $(find -type d ! -path "*/vendor/*" ! -path "*/.git/*" | sort -u); do
	(cd $dir && go list -f '{{if .Standard}}{{.ImportPath}}{{end}}' -e)
done | sort | uniq -c | sort -nr

