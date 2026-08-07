// Command legacy-import is a one-shot SQLite-to-PostgreSQL importer. It is a
// separate module so the panel never links a SQLite driver.
package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

type tableInfo struct { name string; cols, pk, parents []string }
type tableReport struct { Rows int `json:"rows"`; Checksum string `json:"checksum"` }
type targetInfo struct { Host string `json:"host"`; Database string `json:"database"` }
type report struct { Source string `json:"source"`; Target targetInfo `json:"target"`; StartedAt time.Time `json:"started_at"`; EndedAt time.Time `json:"ended_at"`; Tables map[string]tableReport `json:"tables"`; Files map[string]string `json:"files,omitempty"` }

func main() {
	ctx := context.Background()
	source := flag.String("source", os.Getenv("SOURCE"), "SQLite file or PostgreSQL custom dump (also SOURCE)")
	target := flag.String("target", os.Getenv("TARGET_DATABASE_URL"), "PostgreSQL target URL (also TARGET_DATABASE_URL)")
	manifest := flag.String("manifest", "legacy-import-manifest.json", "manifest output path")
	copyFrom := flag.String("copy-from", "", "optional artifact root to copy")
	copyTo := flag.String("copy-to", "", "destination root for --copy-from")
	flag.Parse()
	if *source == "" || *target == "" { fatal("SOURCE and TARGET_DATABASE_URL are required") }
	if strings.TrimSpace(*source) == strings.TrimSpace(*target) { fatal("SOURCE and TARGET_DATABASE_URL must differ") }
	if strings.HasPrefix(strings.ToLower(*source), "postgres://") || strings.HasPrefix(strings.ToLower(*source), "postgresql://") { fatal("SOURCE must be a SQLite file or dump file, not a live database URL") }
	if (*copyFrom == "") != (*copyTo == "") { fatal("--copy-from and --copy-to must be supplied together") }
	started := time.Now().UTC()
	if err := os.MkdirAll(filepath.Dir(*manifest), 0o755); err != nil && filepath.Dir(*manifest) != "." { fatal("manifest directory: %v", err) }
	var r report
	var err error
	if isDump(*source) { err = restoreDump(ctx, *source, *target); r = report{Source: filepath.Clean(*source), Target: redactTarget(*target), StartedAt: started, EndedAt: time.Now().UTC(), Tables: map[string]tableReport{}} } else { r, err = importSQLite(ctx, *source, *target, started) }
	if err == nil && *copyFrom != "" { r.Files, err = copyTree(*copyFrom, *copyTo) }
	if err != nil { fatal("import: %v", err) }
	if err := writeManifest(*manifest, r); err != nil { fatal("write manifest: %v", err) }
}

func importSQLite(ctx context.Context, source, target string, started time.Time) (report, error) {
	r := report{Source: filepath.Clean(source), Target: redactTarget(target), StartedAt: started, Tables: map[string]tableReport{}}
	if _, err := os.Stat(source); err != nil { return r, fmt.Errorf("source: %w", err) }
	src, err := sql.Open("sqlite", source); if err != nil { return r, err }; defer src.Close()
	dst, err := sql.Open("pgx", target); if err != nil { return r, err }; defer dst.Close()
	if err := dst.PingContext(ctx); err != nil { return r, fmt.Errorf("target ping: %w", err) }
	tables, err := sqliteTables(ctx, src); if err != nil { return r, err }; tables, err = orderTables(tables); if err != nil { return r, err }
	for _, t := range tables { n, sum, err := copyTable(ctx, src, dst, t); if err != nil { return r, fmt.Errorf("table %s: %w", t.name, err) }; r.Tables[t.name] = tableReport{Rows:n,Checksum:sum} }
	r.EndedAt = time.Now().UTC(); return r, nil
}

func sqliteTables(ctx context.Context, db *sql.DB) ([]tableInfo, error) {
	rows, err := db.QueryContext(ctx, "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"); if err != nil{return nil,err}; defer rows.Close()
	var out []tableInfo
	for rows.Next(){var n string;if err:=rows.Scan(&n);err!=nil{return nil,err};t,err:=sqliteTable(ctx,db,n);if err!=nil{return nil,err};out=append(out,t)}
	return out,rows.Err()
}
func sqliteTable(ctx context.Context, db *sql.DB, name string) (tableInfo,error) {
	t:=tableInfo{name:name}; rows,err:=db.QueryContext(ctx,"PRAGMA table_info("+quoteSQLite(name)+")");if err!=nil{return t,err};defer rows.Close()
	for rows.Next(){var cid,notnull,pk int;var col,typ string;var d any;if err:=rows.Scan(&cid,&col,&typ,&notnull,&d,&pk);err!=nil{return t,err};t.cols=append(t.cols,col);if pk>0{t.pk=append(t.pk,col)}}
	if err:=rows.Err();err!=nil{return t,err};if len(t.pk)==0{t.pk=append([]string{},t.cols...)}
	fr,err:=db.QueryContext(ctx,"PRAGMA foreign_key_list("+quoteSQLite(name)+")");if err!=nil{return t,err};defer fr.Close();for fr.Next(){var id,seq int;var parent,from,to,onUpdate,onDelete,match string;if err:=fr.Scan(&id,&seq,&parent,&from,&to,&onUpdate,&onDelete,&match);err!=nil{return t,err};t.parents=append(t.parents,parent)};return t,fr.Err()
}
func orderTables(in []tableInfo)([]tableInfo,error){by:=map[string]tableInfo{};for _,t:=range in{by[t.name]=t};var out []tableInfo;done,visiting:=map[string]bool{},map[string]bool{};var visit func(string)error;visit=func(n string)error{if done[n]{return nil};if visiting[n]{return fmt.Errorf("foreign-key cycle includes %s",n)};t,ok:=by[n];if !ok{return nil};visiting[n]=true;for _,p:=range t.parents{if _,ok:=by[p];ok{if err:=visit(p);err!=nil{return err}}};visiting[n]=false;done[n]=true;out=append(out,t);return nil};names:=make([]string,0,len(by));for n:=range by{names=append(names,n)};sort.Strings(names);for _,n:=range names{if err:=visit(n);err!=nil{return nil,err}};return out,nil}

func copyTable(ctx context.Context, src,dst *sql.DB,t tableInfo)(int,string,error){
	rows,err:=src.QueryContext(ctx,"SELECT "+quoted(t.cols)+" FROM "+quote(t.name)+" ORDER BY "+quoted(t.pk));if err!=nil{return 0,"",err};defer rows.Close();insert:="INSERT INTO "+quote(t.name)+" ("+quoted(t.cols)+") VALUES ("+placeholders(len(t.cols))+") ON CONFLICT DO NOTHING";h:=sha256.New();count:=0
	for rows.Next(){vals:=make([]any,len(t.cols));ptrs:=make([]any,len(vals));for i:=range vals{ptrs[i]=&vals[i]};if err:=rows.Scan(ptrs...);err!=nil{return count,"",err};hashVals:=append([]any(nil),vals...);b,err:=canonical(hashVals);if err!=nil{return count,"",err};h.Write(b);h.Write([]byte{'\n'});if _,err:=dst.ExecContext(ctx,insert,vals...);err!=nil{return count,"",err};count++}
	if err:=rows.Err();err!=nil{return count,"",err};sum:=hex.EncodeToString(h.Sum(nil));actual,err:=targetChecksum(ctx,dst,t);if err!=nil{return count,"",err};if actual.Rows!=count||actual.Checksum!=sum{return count,"",fmt.Errorf("verification mismatch: source rows=%d checksum=%s target rows=%d checksum=%s",count,sum,actual.Rows,actual.Checksum)};return count,sum,nil
}
func targetChecksum(ctx context.Context,db *sql.DB,t tableInfo)(tableReport,error){rows,err:=db.QueryContext(ctx,"SELECT "+quoted(t.cols)+" FROM "+quote(t.name)+" ORDER BY "+quoted(t.pk));if err!=nil{return tableReport{},err};defer rows.Close();h:=sha256.New();n:=0;for rows.Next(){vals:=make([]any,len(t.cols));ptrs:=make([]any,len(vals));for i:=range vals{ptrs[i]=&vals[i]};if err:=rows.Scan(ptrs...);err!=nil{return tableReport{},err};b,err:=canonical(vals);if err!=nil{return tableReport{},err};h.Write(b);h.Write([]byte{'\n'});n++};return tableReport{Rows:n,Checksum:hex.EncodeToString(h.Sum(nil))},rows.Err()}
func canonical(v []any)([]byte,error){for i,x:=range v{if b,ok:=x.([]byte);ok{v[i]=hex.EncodeToString(b)}};return json.Marshal(v)}

func copyTree(root,dest string)(map[string]string,error){root,err:=filepath.Abs(root);if err!=nil{return nil,err};dest,err=filepath.Abs(dest);if err!=nil{return nil,err};st,err:=os.Lstat(root);if err!=nil{return nil,err};if st.Mode()&os.ModeSymlink!=0{return nil,errors.New("source root is a symlink")};files:=map[string]string{};err=filepath.Walk(root,func(path string,info os.FileInfo,walkErr error)error{if walkErr!=nil{return walkErr};if info.Mode()&os.ModeSymlink!=0{return errors.New("symlink encountered: "+path)};rel,err:=filepath.Rel(root,path);if err!=nil{return err};if rel=="."{return os.MkdirAll(dest,0o755)};out:=filepath.Join(dest,rel);if !within(dest,out){return errors.New("destination escapes root")};if info.IsDir(){return os.MkdirAll(out,info.Mode().Perm())};if err:=os.MkdirAll(filepath.Dir(out),0o755);err!=nil{return err};in,err:=os.Open(path);if err!=nil{return err};defer in.Close();o,err:=os.OpenFile(out,os.O_CREATE|os.O_TRUNC|os.O_WRONLY,info.Mode().Perm());if err!=nil{return err};h:=sha256.New();if _,err:=io.Copy(io.MultiWriter(o,h),in);err!=nil{o.Close();return err};if err:=o.Close();err!=nil{return err};files[filepath.ToSlash(rel)]=hex.EncodeToString(h.Sum(nil));return nil});return files,err}
func within(root,path string)bool{r,_:=filepath.Rel(root,path);return r!=".."&&!strings.HasPrefix(r,".."+string(os.PathSeparator))}
func restoreDump(ctx context.Context,source,target string)error{cmd:=exec.CommandContext(ctx,"pg_restore","--no-owner","--exit-on-error","--dbname",target,source);cmd.Stdout=os.Stdout;cmd.Stderr=os.Stderr;return cmd.Run()}
func isDump(s string)bool{l:=strings.ToLower(s);return strings.HasSuffix(l,".dump")||strings.HasSuffix(l,".backup")||strings.HasSuffix(l,".tar")}
func redactTarget(raw string)targetInfo{u,err:=url.Parse(raw);if err!=nil{return targetInfo{Host:"invalid",Database:"invalid"}};db:=strings.TrimPrefix(u.Path,"/");return targetInfo{Host:u.Hostname(),Database:db}}
func writeManifest(path string,r report)error{b,err:=json.MarshalIndent(r,"","  ");if err!=nil{return err};return os.WriteFile(path,append(b,'\n'),0o600)}
func quote(s string)string{return `"`+strings.ReplaceAll(s,`"`,`""`)+`"`};func quoteSQLite(s string)string{return `"`+strings.ReplaceAll(s,`"`,`""`)+`"`};func quoted(a []string)string{q:=make([]string,len(a));for i,s:=range a{q[i]=quote(s)};return strings.Join(q,",")};func placeholders(n int)string{a:=make([]string,n);for i:=range a{a[i]=fmt.Sprintf("$%d",i+1)};return strings.Join(a,",")}
func fatal(f string,a ...any){fmt.Fprintf(os.Stderr,"legacy-import: "+f+"\n",a...);os.Exit(1)}
