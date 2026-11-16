"""CIP-003-11 readiness checklist."""
import csv
import io

from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response
from sqlalchemy.orm import Session

from .. import readiness as rd
from ..auth import audit, csrf_protect, current_user, editor
from ..db import get_db
from ..models import Asset, ReadinessItem, User, utcnow
from ..web import d, redirect, render, s
from .inventory import owned

router = APIRouter()


@router.get("/readiness")
def page(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    return render(request, "readiness.html", user, statuses=rd.STATUSES, **rd.load(db, user.org_id))


@router.post("/readiness", dependencies=[Depends(csrf_protect)])
async def save(request: Request, user: User = Depends(editor), db: Session = Depends(get_db)):
    f = await request.form()
    asset = None
    if f.get("asset_id"):
        try:
            asset = owned(db, Asset, int(f["asset_id"]), user)
        except ValueError:
            return redirect("/readiness", "Unknown asset.", request)
    keys = [k for k, *_ in rd.ASSET_ITEMS if rd.applies(asset, k)] if asset else [k for k, *_ in rd.ORG_ITEMS]
    changed = []
    for k in keys:
        st = f.get(f"status_{k}")
        if st not in rd.STATUSES:
            continue
        row = db.query(ReadinessItem).filter_by(org_id=user.org_id, asset_id=asset.id if asset else None,
                                                key=k).first()
        vals = dict(status=st, method=s(f, f"method_{k}"), owner=s(f, f"owner_{k}"), target_date=d(f, f"target_{k}"))
        if row and all(getattr(row, a) == v for a, v in vals.items()):
            continue
        if not row:
            if st == "Not started" and not any([vals["method"], vals["owner"], vals["target_date"]]):
                continue
            row = ReadinessItem(org_id=user.org_id, asset_id=asset.id if asset else None, key=k)
            db.add(row)
        for a, v in vals.items():
            setattr(row, a, v)
        row.updated_by, row.updated_at = user.email, utcnow()
        changed.append(f"{k}={st}")
    if changed:
        audit(db, user, "readiness_updated", f"{asset.name if asset else 'Organization'}: {', '.join(changed)}")
    db.commit()
    return redirect(f"/readiness#{'a' + str(asset.id) if asset else 'org'}",
                    f"Saved {len(changed)} change(s)." if changed else "No changes.", request)


@router.get("/readiness.csv")
def export(user: User = Depends(current_user), db: Session = Depends(get_db)):
    data = rd.load(db, user.org_id)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["Scope", "Item", "Title", "Status", "Method", "Owner", "Target date", "PrismCIP note", "Updated by",
                "Updated at"])

    def line(scope, key, title, row, hint=None):
        w.writerow([scope, key, title, row.status if row else "Not started", row.method if row else "",
                    row.owner if row else "", row.target_date or "" if row else "", hint[0] if hint else "",
                    row.updated_by if row else "", row.updated_at.isoformat(timespec="minutes") if row and
                    row.updated_at else ""])
    for i in data["org_rows"]:
        line("Organization", i["code"], i["title"], i["row"])
    for pa in data["per_asset"]:
        for i in pa["rows"]:
            line(pa["asset"].name, "Att. 1 S" + i["key"], i["title"], i["row"], i["hint"])
    return Response(buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": 'attachment; filename="cip-003-11-readiness.csv"'})
