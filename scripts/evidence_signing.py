"""Ed25519 signatures for review-evidence roots."""
from __future__ import annotations
import argparse, base64, json, re, sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
SCHEMA_VERSION=1
DOMAIN=b"system-design-primer-review-evidence-signature-v1\0"
KEY_ID_RE=re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
SIGNATURE_FIELDS={"schema_version","algorithm","key_id","signed_at","evidence_root","signature"}
def canonical_json(value: Any) -> bytes:
 return json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(",",":")).encode("utf-8")
def load_report(path: Path) -> dict[str,Any]:
 report=json.loads(path.read_text(encoding="utf-8"))
 if not isinstance(report,dict): raise ValueError("report must be a JSON object")
 try: from .review_evidence import verify_report_evidence
 except ImportError: from review_evidence import verify_report_evidence
 verify_report_evidence(report)
 if not isinstance(report.get("review_evidence_root"),str): raise ValueError("missing evidence root")
 return report
def payload(key_id: str,signed_at: str,root: str) -> bytes:
 return DOMAIN+canonical_json({"schema_version":SCHEMA_VERSION,"algorithm":"Ed25519","key_id":key_id,"signed_at":signed_at,"evidence_root":root})
def sign_report(report_path: Path,private_path: Path,key_id: str) -> dict[str,Any]:
 if not KEY_ID_RE.fullmatch(key_id): raise ValueError("invalid key_id")
 report=load_report(report_path); key=serialization.load_pem_private_key(private_path.read_bytes(),password=None)
 if not isinstance(key,Ed25519PrivateKey): raise ValueError("private key must be an unencrypted Ed25519 PEM key")
 signed_at=datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00","Z"); root=report["review_evidence_root"]
 signature=key.sign(payload(key_id,signed_at,root))
 return {"schema_version":SCHEMA_VERSION,"algorithm":"Ed25519","key_id":key_id,"signed_at":signed_at,"evidence_root":root,"signature":base64.b64encode(signature).decode("ascii")}
def verify_signature(report_path: Path,signature_path: Path,trust_path: Path) -> dict[str,Any]:
 report=load_report(report_path); envelope=json.loads(signature_path.read_text(encoding="utf-8"))
 if not isinstance(envelope,dict) or set(envelope)!=SIGNATURE_FIELDS or envelope.get("schema_version")!=SCHEMA_VERSION or envelope.get("algorithm")!="Ed25519": raise ValueError("invalid signature envelope schema")
 key_id=envelope.get("key_id"); signed_at=envelope.get("signed_at"); root=envelope.get("evidence_root")
 if not isinstance(key_id,str) or not KEY_ID_RE.fullmatch(key_id): raise ValueError("invalid key_id")
 if not isinstance(signed_at,str) or not signed_at.endswith("Z"): raise ValueError("signed_at must be UTC RFC3339")
 try: datetime.fromisoformat(signed_at[:-1]+"+00:00")
 except ValueError as exc: raise ValueError("invalid signed_at timestamp") from exc
 if root!=report.get("review_evidence_root"): raise ValueError("signature evidence root does not match report")
 store=json.loads(trust_path.read_text(encoding="utf-8"))
 if not isinstance(store,dict) or store.get("schema_version")!=1 or not isinstance(store.get("keys"),dict): raise ValueError("invalid trust store schema")
 entry=store["keys"].get(key_id)
 if not isinstance(entry,dict) or set(entry)!={"public_key_pem","status"}: raise ValueError("unknown or malformed trust-store key")
 if entry["status"]!="active": raise ValueError("signing key is not active (revoked or disabled)")
 public=serialization.load_pem_public_key(entry["public_key_pem"].encode("ascii"))
 if not isinstance(public,Ed25519PublicKey): raise ValueError("trust-store key must be Ed25519")
 try: public.verify(base64.b64decode(envelope["signature"],validate=True),payload(key_id,signed_at,root))
 except Exception as exc: raise ValueError("Ed25519 signature verification failed") from exc
 return {"verified":True,"algorithm":"Ed25519","key_id":key_id,"signed_at":signed_at,"evidence_root":root}
def main() -> int:
 p=argparse.ArgumentParser(description=__doc__); sub=p.add_subparsers(dest="command",required=True)
 s=sub.add_parser("sign"); s.add_argument("--report",type=Path,required=True); s.add_argument("--private-key",type=Path,required=True); s.add_argument("--key-id",required=True); s.add_argument("--output",type=Path,required=True)
 v=sub.add_parser("verify"); v.add_argument("--report",type=Path,required=True); v.add_argument("--signature",type=Path,required=True); v.add_argument("--trust-store",type=Path,required=True)
 a=p.parse_args()
 try:
  if a.command=="sign":
   result=sign_report(a.report,a.private_key,a.key_id); a.output.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n",encoding="utf-8")
   result={"signed":True,"key_id":result["key_id"],"evidence_root":result["evidence_root"],"output":str(a.output)}
  else: result=verify_signature(a.report,a.signature,a.trust_store)
 except (OSError,json.JSONDecodeError,ValueError,TypeError) as exc: print("ERROR: "+str(exc),file=sys.stderr); return 1
 print(json.dumps(result,sort_keys=True,indent=2)); return 0
if __name__=="__main__": raise SystemExit(main())