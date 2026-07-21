from __future__ import annotations
import json, re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data" / "dorks.json"
RAW = Path("/sessions/funny-compassionate-lamport/mnt/.claude/projects")
SRC_DIR = Path(__file__).resolve().parent

OP = re.compile(
    r"(\b(site|inurl|allinurl|intitle|allintitle|intext|allintext|filetype|ext|"
    r"cache|link|related|inanchor|allinanchor|numrange|insite|around|before|after)\s*:)"
    r'|("index of")|("parent directory")|(index\.of)', re.IGNORECASE)
TRANS = {"“":'"',"”":'"',"‘":"'","’":"'","″":'"'," ":" "}

def norm(s):
    for a,b in TRANS.items(): s=s.replace(a,b)
    return re.sub(r"\s+"," ",s).strip()

def is_dork(s):
    return bool(s) and not s.startswith("#") and len(s)>=5 and bool(OP.search(s))

def parse_blocks(text, defcat):
    out=[]; cur=defcat
    for ln in text.splitlines():
        raw=ln.rstrip(); s=norm(raw)
        if not s: continue
        if raw.lstrip().startswith("#"):
            name=raw.strip("# ").strip(" =")
            if name and not OP.search(name): cur=f"{defcat} · {name}"
            continue
        m=re.match(r"^([A-Z][A-Za-z0-9 /()\-]{3,50}):\s*$", raw.strip())
        if m and not OP.search(raw):
            cur=f"{defcat} · {m.group(1).strip()}"; continue
        if is_dork(s): out.append((cur,s))
    return out

def find_raw(frag):
    for p in RAW.rglob("mcp-workspace-web_fetch-*.txt"):
        try: head=p.read_text(errors="ignore")[:200]
        except: continue
        if frag in head: return p.read_text(errors="ignore")
    return None

bullseye=find_raw("BullsEye0/google_dork_list")

SRC_GIT="""inurl:.git-credentials
inurl:.gitconfig
intext:"index of /.git" "parent directory"
filetype:git -github.com inurl:"/.git"
inurl:ORIG_HEAD
intitle:"index of" ".gitignore"
".git" intitle:"Index of"
"Parent Directory" "Last modified" git"""
SRC_AWS="""site:s3.amazonaws.com intitle:index.of.bucket
site:amazonaws.com inurl:".s3.amazonaws.com/"
site:.s3.amazonaws.com "Company"
intitle:index.of.bucket
site:s3.amazonaws.com intitle:Bucket loading
site:*.amazonaws.com inurl:index.html"""

def load(n):
    p=SRC_DIR/n; return p.read_text(encoding="utf-8",errors="ignore") if p.exists() else ""

sources=[
 ("git", SRC_GIT, "Git Files (Proviesec)"),
 ("aws", SRC_AWS, "AWS S3 (Proviesec)"),
 ("log", load("proviesec_best_log.txt"), "Log Files (Proviesec)"),
 ("bb", load("sushiwushi_dorks.txt"), "Bug Bounty (sushiwushi)"),
 ("infosec", load("infosec_hidden_files.txt"), "InfoSec Dorks (0xAbbarhSF)"),
]
if bullseye: sources.append(("bullseye", bullseye, "Google Dorks (BullsEye0)"))

data=json.loads(DATA.read_text(encoding="utf-8"))
cats=data["categories"]
seen=set(); by_cat={}
for c in cats:
    by_cat[c["category"]]=c
    for d in c["dorks"]: seen.add(norm(d).lower())

added=0; per={}
for tag,text,defcat in sources:
    cnt=0
    for cat,dork in parse_blocks(text,defcat):
        k=dork.lower()
        if k in seen: continue
        seen.add(k)
        t=by_cat.get(cat)
        if t is None:
            t={"category":cat,"dorks":[]}; by_cat[cat]=t; cats.append(t)
        t["dorks"].append(dork); cnt+=1; added+=1
    per[defcat]=per.get(defcat,0)+cnt

data["source"]="GDorks + BullsEye0 + Proviesec + sushiwushi + 0xAbbarhSF (via cipher387 collection)"
DATA.write_text(json.dumps(data,ensure_ascii=False,indent=1),encoding="utf-8")
total=sum(len(c["dorks"]) for c in cats)
print("Nuevos por fuente:")
for k,v in per.items(): print(f"  {k}: +{v}")
print(f"TOTAL nuevos: {added}")
print(f"TOTAL dorks: {total} en {len(cats)} categorias")
