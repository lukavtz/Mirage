// Command postgresql-cutover creates an immutable source backup and operator
// manifest. It is never called by panel startup.
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
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

type targetInfo struct { Host string `json:"host"`; Database string `json:"database"` }
type tableReport struct { Rows int `json:"rows"`; Checksum string `json:"checksum"` }
type manifest struct { Source string `json:"source"`; Target targetInfo `json:"target"`; StartedAt time.Time `json:"started_at"`; EndedAt time.Time `json:"ended_at"`; Backup string `json:"backup"`; BackupSHA256 string `json:"backup_sha256"`; Tables map[string]tableReport `json:"tables"`; Files map[string]string `json:"files"` }

func main() {
	ctx:=context.Background(); source:=flag.String("source",os.Getenv("SOURCE"),"source PostgreSQL URL or SQLite path (also SOURCE)");target:=flag.String("target",os.Getenv("TARGET_DATABASE_URL"),"disposable PostgreSQL target URL (also TARGET_DATABASE_URL)");out:=flag.String("backup-dir","backups","immutable backup directory");manifestPath:=flag.String("manifest","cutover-manifest.json","manifest output path");copyRoots:=multiFlag{};flag.Var(&copyRoots,"copy-root","filesystem root to checksum (repeatable)");flag.Parse()
	if *source==""||*target==""{fatal("SOURCE and TARGET_DATABASE_URL are required")};if strings.TrimSpace(*source)==strings.TrimSpace(*target){fatal("SOURCE and TARGET_DATABASE_URL must differ")};if err:=os.MkdirAll(*out,0o755);err!=nil{fatal("backup directory: %v",err)};if err:=os.MkdirAll(filepath.Dir(*manifestPath),0o755);err!=nil&&filepath.Dir(*manifestPath)!="."{fatal("manifest directory: %v",err)}
	started:=time.Now().UTC();backup,err:=createBackup(ctx,*source,*target,*out);if err!=nil{fatal("backup: %v",err)};r:=manifest{Source:redactSource(*source),Target:redactTarget(*target),StartedAt:started,Backup:backup,Tables:map[string]tableReport{},Files:map[string]string{}};r.BackupSHA256,err=fileHash(backup);if err!=nil{fatal("backup checksum: %v",err)}
	if strings.HasPrefix(strings.ToLower(*source),"postgres://")||strings.HasPrefix(strings.ToLower(*source),"postgresql://"){r.Tables,err=databaseReport(ctx,*source);if err!=nil{fatal("source report: %v",err)}}
	for _,root:=range copyRoots{m,e:=checksumTree(root);if e!=nil{fatal("filesystem %s: %v",root,e)};for p,h:=range m{r.Files[p]=h}}
	r.EndedAt=time.Now().UTC();if err:=writeManifest(*manifestPath,r);err!=nil{fatal("manifest: %v",err)}
}
type multiFlag []string
func (m *multiFlag)String()string{return strings.Join(*m,",")};func(m *multiFlag)Set(v string)error{*m=append(*m,v);return nil}
func createBackup(ctx context.Context,source,target,dir string)(string,error){	if strings.HasPrefix(strings.ToLower(source),"postgres://")||strings.HasPrefix(strings.ToLower(source),"postgresql://"){name:=filepath.Join(dir,"source-"+time.Now().UTC().Format("20060102T150405Z")+".dump");cmd:=exec.CommandContext(ctx,"pg_dump","--format=custom","--no-owner","--file",name,source);cmd.Stdout=os.Stdout;cmd.Stderr=os.Stderr;if err:=cmd.Run();err!=nil{return "",err};return name,nil};st,err:=os.Lstat(source);if err!=nil{return "",err};if st.Mode()&os.ModeSymlink!=0{return "",errors.New("source SQLite path is a symlink")};name:=filepath.Join(dir,"legacy-"+time.Now().UTC().Format("20060102T150405Z")+".db");return name,copyFile(source,name)}
func databaseReport(ctx context.Context,raw string)(map[string]tableReport,error){db,err:=sql.Open("pgx",raw);if err!=nil{return nil,err};defer db.Close();if err:=db.PingContext(ctx);err!=nil{return nil,err};rows,err:=db.QueryContext(ctx,"SELECT table_name FROM information_schema.tables WHERE table_schema='public' ORDER BY table_name");if err!=nil{return nil,err};defer rows.Close();out:=map[string]tableReport{};for rows.Next(){var n string;if err:=rows.Scan(&n);err!=nil{return nil,err};var count int; if err:=db.QueryRowContext(ctx,"SELECT count(*) FROM "+quote(n)).Scan(&count);err!=nil{return nil,err};out[n]=tableReport{Rows:count}};return out,rows.Err()}
func checksumTree(root string)(map[string]string,error){root,err:=filepath.Abs(root);if err!=nil{return nil,err};st,err:=os.Lstat(root);if err!=nil{return nil,err};if st.Mode()&os.ModeSymlink!=0{return nil,errors.New("root is a symlink")};out:=map[string]string{};err=filepath.Walk(root,func(path string,info os.FileInfo,e error)error{if e!=nil{return e};if info.Mode()&os.ModeSymlink!=0{return errors.New("symlink encountered: "+path)};if info.IsDir(){return nil};h,e:=fileHash(path);if e!=nil{return e};rel,_:=filepath.Rel(root,path);out[filepath.ToSlash(filepath.Join(root,rel))]=h;return nil});return out,err}
func copyFile(src,dst string)error{in,e:=os.Open(src);if e!=nil{return e};defer in.Close();out,e:=os.OpenFile(dst,os.O_CREATE|os.O_EXCL|os.O_WRONLY,0o600);if e!=nil{return e};defer out.Close();_,e=io.Copy(out,in);return e}
func fileHash(path string)(string,error){f,e:=os.Open(path);if e!=nil{return "",e};defer f.Close();h:=sha256.New();if _,e:=io.Copy(h,f);e!=nil{return "",e};return hex.EncodeToString(h.Sum(nil)),nil}
func redactSource(s string)string{if u,e:=url.Parse(s);e==nil&&u.Scheme!=""{u.User=nil;u.RawQuery="";return u.String()};return filepath.Clean(s)}
func redactTarget(s string)targetInfo{u,e:=url.Parse(s);if e!=nil{return targetInfo{Host:"invalid",Database:"invalid"}};return targetInfo{Host:u.Hostname(),Database:strings.TrimPrefix(u.Path,"/")}}
func writeManifest(path string,m manifest)error{b,e:=json.MarshalIndent(m,"","  ");if e!=nil{return e};return os.WriteFile(path,append(b,'\n'),0o600)}
func quote(s string)string{return `"`+strings.ReplaceAll(s,`"`,`""`)+`"`};func fatal(f string,a ...any){fmt.Fprintf(os.Stderr,"postgresql-cutover: "+f+"\n",a...);os.Exit(1)}
