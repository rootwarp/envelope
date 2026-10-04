package pipeline

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// parkedCtx holds the command context for the signal-test binary's plugin
// prompt. That process is started by an exec'd test, so the context cannot
// be passed in, and the variable is compiled only into that binary.
//
// link replaces os.Link inside the fake plugin. Production never imports
// that package, so the replacement cannot affect a real run.
//
// The signal-test binary and the ordinary binary each define defaultDeps,
// selected by build tag. The exec'd process cannot be handed a value, so
// the tag is the selection.
//
// Seven terminal hooks remain. Tests in that package replace them, and the
// real terminal tests cover the production path. No test replaced signal
// notification, so that call is not a hook.
func TestPackageSeamExceptions(t *testing.T) {
	root := moduleRoot(t)
	gotSeams, gotDefaults := enumerateSeams(t, root)
	wantSeams := []string{
		"internal/key/tty/tty.go getState",
		"internal/key/tty/tty.go noEcho",
		"internal/key/tty/tty.go readLine",
		"internal/key/tty/tty.go readPassword",
		"internal/key/tty/tty.go restoreState",
		"internal/key/tty/tty.go signalStop",
		"internal/key/tty/tty.go watchSignal",
		"internal/pipeline/signalhook.go parkedCtx",
		"test/fakeplugin/fakeplugin.go link",
	}
	wantDefaults := []string{
		"internal/pipeline/deps_default.go",
		"internal/pipeline/signalhook.go",
	}
	if !reflect.DeepEqual(gotSeams, wantSeams) || !reflect.DeepEqual(gotDefaults, wantDefaults) {
		t.Fatalf("mutable seams = %v\ndefaults = %v\nwant seams %v\nwant defaults %v",
			gotSeams, gotDefaults, wantSeams, wantDefaults)
	}
}

// A function value is a seam even when nothing assigns it, and a qualified
// assignment from another package counts. An inner short declaration must
// not hide an earlier assignment of the package variable, and a select
// clause short declaration must not hide a later one.
func TestSeamClassifierHoles(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "go.mod"), "module example.com/m\n")
	writeFile(t, filepath.Join(root, "p", "hooks.go"), `package p

import "os"

var signalNotify = os.Link
var ErrAlias = os.ErrInvalid
var count int
var visible int
var onlyLocal int
var replaced int
var afterSelect int
var fromClause int

func helper() {}

var hook = helper

func notASeam() {}

func use() {
	count = 1
	{
		count := 0
		count = 2
	}
	{
		onlyLocal := 1
		onlyLocal = 2
	}
	{
		visible := 0
		_ = visible
	}
	visible = 1
}

func useSelect(ch, other chan int) {
	select {
	case afterSelect := <-ch:
	case fromClause := <-other:
	case fromClause = <-ch:
	}
	afterSelect = 1
}
`)
	writeFile(t, filepath.Join(root, "q", "q.go"), `package q

import "example.com/m/p"

func g() {
	p.replaced = 1
}
`)
	got, defaults := enumerateSeams(t, root)
	want := []string{
		"p/hooks.go afterSelect",
		"p/hooks.go count",
		"p/hooks.go fromClause",
		"p/hooks.go hook",
		"p/hooks.go replaced",
		"p/hooks.go signalNotify",
		"p/hooks.go visible",
	}
	if !reflect.DeepEqual(got, want) || len(defaults) != 0 {
		t.Fatalf("seams = %v\ndefaults = %v\nwant %v", got, defaults, want)
	}
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func enumerateSeams(t *testing.T, root string) (seams, defaults []string) {
	t.Helper()
	mod := modulePath(t, root)
	fset := token.NewFileSet()
	type fileAST struct {
		rel  string
		dir  string
		f    *ast.File
		test bool
	}
	type pkgKey struct {
		dir string
		pkg string
	}
	byPkg := map[pkgKey][]fileAST{}
	// dir/name → declaring file, for qualified assignments from other packages.
	declared := map[string]map[string]string{}
	var pending []struct{ dir, name string }
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "vendor", "bin":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		dir := filepath.ToSlash(filepath.Dir(rel))
		if dir == "." {
			dir = ""
		}
		test := strings.HasSuffix(path, "_test.go")
		key := pkgKey{dir: dir, pkg: f.Name.Name}
		byPkg[key] = append(byPkg[key], fileAST{rel: rel, dir: dir, f: f, test: test})
		if !test && funcNamed(f, "defaultDeps") && buildSelectsSignaltest(f) {
			defaults = append(defaults, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// Function values are seams when declared. Other package state is a seam
	// only when something assigns it. A function declaration is not a var.
	seen := map[string]struct{}{}
	for _, files := range byPkg {
		funcs := map[string]bool{}
		pkgVars := map[string]bool{}
		var decls []fileAST
		for _, file := range files {
			if file.test {
				continue
			}
			decls = append(decls, file)
			for _, name := range funcNames(file.f) {
				funcs[name] = true
			}
			if declared[file.dir] == nil {
				declared[file.dir] = map[string]string{}
			}
			for _, name := range packageVarNames(file.f) {
				pkgVars[name] = true
				if _, ok := declared[file.dir][name]; !ok {
					declared[file.dir][name] = file.rel
				}
			}
		}
		for _, file := range decls {
			for _, name := range funcValuedVars(file.f, funcs) {
				seen[file.rel+" "+name] = struct{}{}
			}
		}
		assigned := map[string]bool{}
		var sels []selAssign
		for _, file := range files {
			locals, qual := assignedInFile(file.f, pkgVars)
			for _, name := range locals {
				assigned[name] = true
			}
			sels = append(sels, qual...)
		}
		for _, decl := range decls {
			for _, name := range packageVarNames(decl.f) {
				if assigned[name] {
					seen[decl.rel+" "+name] = struct{}{}
				}
			}
		}
		for _, sa := range sels {
			path, ok := importPaths(sa.file)[sa.qual]
			if !ok || !strings.HasPrefix(path, mod+"/") {
				continue
			}
			pending = append(pending, struct{ dir, name string }{
				dir:  strings.TrimPrefix(path, mod+"/"),
				name: sa.name,
			})
		}
	}
	for _, sa := range pending {
		if rel, ok := declared[sa.dir][sa.name]; ok {
			seen[rel+" "+sa.name] = struct{}{}
		}
	}
	for name := range seen {
		seams = append(seams, name)
	}
	sort.Strings(seams)
	sort.Strings(defaults)
	return seams, defaults
}

func modulePath(t *testing.T, root string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	line, _, _ := strings.Cut(string(b), "\n")
	fields := strings.Fields(line)
	if len(fields) < 2 || fields[0] != "module" {
		t.Fatalf("go.mod module line: %q", line)
	}
	return fields[1]
}

func packageVarNames(f *ast.File) []string {
	var names []string
	for _, d := range f.Decls {
		gen, ok := d.(*ast.GenDecl)
		if !ok || gen.Tok != token.VAR {
			continue
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for _, name := range vs.Names {
				if name.Name == "_" {
					continue
				}
				names = append(names, name.Name)
			}
		}
	}
	return names
}

func funcNames(f *ast.File) []string {
	var names []string
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if ok && fn.Recv == nil && fn.Name != nil {
			names = append(names, fn.Name.Name)
		}
	}
	return names
}

func funcValuedVars(f *ast.File, funcs map[string]bool) []string {
	var names []string
	for _, d := range f.Decls {
		gen, ok := d.(*ast.GenDecl)
		if !ok || gen.Tok != token.VAR {
			continue
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range vs.Names {
				if name.Name == "_" {
					continue
				}
				if funcValue(vs, i, funcs) {
					names = append(names, name.Name)
				}
			}
		}
	}
	return names
}

func funcValue(vs *ast.ValueSpec, i int, funcs map[string]bool) bool {
	if _, ok := vs.Type.(*ast.FuncType); ok {
		return true
	}
	if vs.Type != nil || i >= len(vs.Values) {
		return false
	}
	// One call returning several values is not a function hook per name.
	if len(vs.Names) > 1 && len(vs.Values) == 1 {
		return false
	}
	switch v := vs.Values[i].(type) {
	case *ast.FuncLit:
		return true
	case *ast.Ident:
		return funcs[v.Name]
	case *ast.SelectorExpr:
		// key.ErrBadRecipient is an error value. os.Link and signal.Notify are hooks.
		return !strings.HasPrefix(v.Sel.Name, "Err")
	default:
		return false
	}
}

type selAssign struct {
	file *ast.File
	qual string
	name string
}

func assignedInFile(f *ast.File, pkgVars map[string]bool) (locals []string, sels []selAssign) {
	localHit := map[string]bool{}
	selHit := map[string]bool{}
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		s := &scope{names: map[string]bool{}}
		addFields(s, fn.Recv)
		if fn.Type != nil {
			addFields(s, fn.Type.Params)
			addFields(s, fn.Type.Results)
		}
		walkBody(fn.Body, s, func(as *ast.AssignStmt, sc *scope) {
			for _, lhs := range as.Lhs {
				switch lhs := lhs.(type) {
				case *ast.Ident:
					if lhs.Name == "_" || sc.has(lhs.Name) || !pkgVars[lhs.Name] || localHit[lhs.Name] {
						continue
					}
					localHit[lhs.Name] = true
					locals = append(locals, lhs.Name)
				case *ast.SelectorExpr:
					id, ok := lhs.X.(*ast.Ident)
					if !ok || sc.has(id.Name) {
						continue
					}
					k := id.Name + "." + lhs.Sel.Name
					if selHit[k] {
						continue
					}
					selHit[k] = true
					sels = append(sels, selAssign{file: f, qual: id.Name, name: lhs.Sel.Name})
				}
			}
		})
	}
	return locals, sels
}

func importPaths(f *ast.File) map[string]string {
	out := map[string]string{}
	for _, im := range f.Imports {
		path, err := strconv.Unquote(im.Path.Value)
		if err != nil {
			continue
		}
		if im.Name != nil {
			if im.Name.Name == "_" || im.Name.Name == "." {
				continue
			}
			out[im.Name.Name] = path
			continue
		}
		if i := strings.LastIndex(path, "/"); i >= 0 {
			out[path[i+1:]] = path
			continue
		}
		out[path] = path
	}
	return out
}

type scope struct {
	parent *scope
	names  map[string]bool
}

func (s *scope) child() *scope {
	return &scope{parent: s, names: map[string]bool{}}
}

func (s *scope) has(name string) bool {
	for p := s; p != nil; p = p.parent {
		if p.names[name] {
			return true
		}
	}
	return false
}

func (s *scope) set(name string) {
	if name != "" && name != "_" {
		s.names[name] = true
	}
}

func addFields(s *scope, list *ast.FieldList) {
	if list == nil {
		return
	}
	for _, field := range list.List {
		for _, name := range field.Names {
			s.set(name.Name)
		}
	}
}

func walkBody(body *ast.BlockStmt, s *scope, onAssign func(*ast.AssignStmt, *scope)) {
	if body == nil {
		return
	}
	for _, st := range body.List {
		walkStmt(st, s, onAssign)
	}
}

func walkStmt(st ast.Stmt, s *scope, onAssign func(*ast.AssignStmt, *scope)) {
	switch st := st.(type) {
	case nil:
	case *ast.BlockStmt:
		inner := s.child()
		for _, c := range st.List {
			walkStmt(c, inner, onAssign)
		}
	case *ast.AssignStmt:
		for _, rhs := range st.Rhs {
			walkExpr(rhs, s, onAssign)
		}
		if st.Tok == token.DEFINE {
			for _, lhs := range st.Lhs {
				id, ok := lhs.(*ast.Ident)
				if !ok || id.Name == "_" {
					continue
				}
				if !s.names[id.Name] {
					s.set(id.Name)
				}
			}
			return
		}
		if st.Tok == token.ASSIGN {
			onAssign(st, s)
		}
	case *ast.DeclStmt:
		gen, ok := st.Decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.VAR {
			return
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for _, val := range vs.Values {
				walkExpr(val, s, onAssign)
			}
			for _, name := range vs.Names {
				s.set(name.Name)
			}
		}
	case *ast.IfStmt:
		inner := s.child()
		walkStmt(st.Init, inner, onAssign)
		walkExpr(st.Cond, inner, onAssign)
		walkBody(st.Body, inner.child(), onAssign)
		walkStmt(st.Else, s, onAssign)
	case *ast.ForStmt:
		inner := s.child()
		walkStmt(st.Init, inner, onAssign)
		walkExpr(st.Cond, inner, onAssign)
		walkStmt(st.Post, inner, onAssign)
		walkBody(st.Body, inner.child(), onAssign)
	case *ast.RangeStmt:
		walkExpr(st.X, s, onAssign)
		inner := s.child()
		if st.Tok == token.DEFINE {
			addRangeIdent(inner, st.Key)
			addRangeIdent(inner, st.Value)
		} else if st.Tok == token.ASSIGN {
			onAssign(&ast.AssignStmt{Lhs: rangeIdents(st), Tok: token.ASSIGN}, s)
		}
		walkBody(st.Body, inner.child(), onAssign)
	case *ast.SwitchStmt:
		inner := s.child()
		walkStmt(st.Init, inner, onAssign)
		walkExpr(st.Tag, inner, onAssign)
		walkCases(st.Body, inner, onAssign)
	case *ast.TypeSwitchStmt:
		inner := s.child()
		walkStmt(st.Init, inner, onAssign)
		walkStmt(st.Assign, inner, onAssign)
		walkCases(st.Body, inner, onAssign)
	case *ast.SelectStmt:
		if st.Body == nil {
			return
		}
		for _, c := range st.Body.List {
			comm, ok := c.(*ast.CommClause)
			if !ok {
				continue
			}
			// A short declaration in the clause ends with the clause. Leaving
			// it on the enclosing scope hides a later write of the package var.
			clause := s.child()
			walkStmt(comm.Comm, clause, onAssign)
			walkBody(&ast.BlockStmt{List: comm.Body}, clause, onAssign)
		}
	case *ast.ReturnStmt:
		for _, r := range st.Results {
			walkExpr(r, s, onAssign)
		}
	case *ast.ExprStmt:
		walkExpr(st.X, s, onAssign)
	case *ast.GoStmt:
		if st.Call != nil {
			walkExpr(st.Call, s, onAssign)
		}
	case *ast.DeferStmt:
		if st.Call != nil {
			walkExpr(st.Call, s, onAssign)
		}
	case *ast.SendStmt:
		walkExpr(st.Chan, s, onAssign)
		walkExpr(st.Value, s, onAssign)
	case *ast.IncDecStmt:
		walkExpr(st.X, s, onAssign)
	case *ast.LabeledStmt:
		walkStmt(st.Stmt, s, onAssign)
	default:
		ast.Inspect(st, func(n ast.Node) bool {
			if n == st {
				return true
			}
			lit, ok := n.(*ast.FuncLit)
			if !ok {
				return true
			}
			walkFuncLit(lit, s, onAssign)
			return false
		})
	}
}

func walkCases(body *ast.BlockStmt, s *scope, onAssign func(*ast.AssignStmt, *scope)) {
	if body == nil {
		return
	}
	for _, c := range body.List {
		clause, ok := c.(*ast.CaseClause)
		if !ok {
			continue
		}
		for _, e := range clause.List {
			walkExpr(e, s, onAssign)
		}
		walkBody(&ast.BlockStmt{List: clause.Body}, s.child(), onAssign)
	}
}

func walkExpr(e ast.Expr, s *scope, onAssign func(*ast.AssignStmt, *scope)) {
	if e == nil {
		return
	}
	ast.Inspect(e, func(n ast.Node) bool {
		lit, ok := n.(*ast.FuncLit)
		if !ok {
			return true
		}
		walkFuncLit(lit, s, onAssign)
		return false
	})
}

func walkFuncLit(lit *ast.FuncLit, parent *scope, onAssign func(*ast.AssignStmt, *scope)) {
	inner := parent.child()
	if lit.Type != nil {
		addFields(inner, lit.Type.Params)
		addFields(inner, lit.Type.Results)
	}
	walkBody(lit.Body, inner, onAssign)
}

func addRangeIdent(s *scope, e ast.Expr) {
	id, ok := e.(*ast.Ident)
	if ok {
		s.set(id.Name)
	}
}

func rangeIdents(st *ast.RangeStmt) []ast.Expr {
	var lhs []ast.Expr
	if st.Key != nil {
		lhs = append(lhs, st.Key)
	}
	if st.Value != nil {
		lhs = append(lhs, st.Value)
	}
	return lhs
}

func funcNamed(f *ast.File, name string) bool {
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if ok && fn.Recv == nil && fn.Name.Name == name {
			return true
		}
	}
	return false
}

func buildSelectsSignaltest(f *ast.File) bool {
	for _, group := range f.Comments {
		for _, c := range group.List {
			line := strings.TrimSpace(c.Text)
			if strings.HasPrefix(line, "//go:build ") && strings.Contains(line, "envelope_signaltest") {
				return true
			}
		}
	}
	return false
}
