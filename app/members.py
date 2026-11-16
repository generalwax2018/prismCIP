"""Memberships: who can work in which utility, with what role.

User.org_id, User.role and User.can_sign always describe the utility the person is currently working in, so
every page keeps scoping by user.org_id. Membership rows are the source of truth across utilities.
"""
from sqlalchemy.orm import Session

from .models import Membership, Organization, User


def ensure_memberships(db: Session) -> int:
    """Give every user a membership for their current organization (upgrades from single-utility installs)."""
    have = {(m.user_id, m.org_id) for m in db.query(Membership).all()}
    n = 0
    for u in db.query(User).all():
        if (u.id, u.org_id) not in have:
            db.add(Membership(user_id=u.id, org_id=u.org_id, role=u.role, can_sign=bool(u.can_sign)))
            n += 1
    if n:
        db.commit()
    return n


def _heal(db: Session, org_id: int) -> None:
    """Users created directly (scripts, older versions) get a membership for the utility they're in."""
    missing = (db.query(User).filter(User.org_id == org_id)
               .filter(~User.id.in_(db.query(Membership.user_id).filter(Membership.org_id == org_id))).all())
    for u in missing:
        db.add(Membership(user_id=u.id, org_id=org_id, role=u.role, can_sign=bool(u.can_sign)))
    if missing:
        db.flush()


def members(db: Session, org_id: int, *, active_only: bool = False, signers_only: bool = False,
            notify_only: bool = False) -> list[tuple[User, Membership]]:
    _heal(db, org_id)
    q = db.query(User, Membership).join(Membership, Membership.user_id == User.id).filter(Membership.org_id == org_id)
    if active_only:
        q = q.filter(User.active.is_(True))
    if signers_only:
        q = q.filter(Membership.can_sign.is_(True))
    if notify_only:
        q = q.filter(User.notify.is_(True))
    return q.order_by(User.name).all()


def member_users(db: Session, org_id: int, **kw) -> list[User]:
    return [u for u, _m in members(db, org_id, **kw)]


def membership(db: Session, user_id: int, org_id: int) -> Membership | None:
    m = db.query(Membership).filter_by(user_id=user_id, org_id=org_id).first()
    if m is None:
        u = db.get(User, user_id)
        if u and u.org_id == org_id:
            _heal(db, org_id)
            m = db.query(Membership).filter_by(user_id=user_id, org_id=org_id).first()
    return m


def orgs_for(db: Session, user: User) -> list[tuple[Organization, Membership]]:
    return (db.query(Organization, Membership).join(Membership, Membership.org_id == Organization.id)
            .filter(Membership.user_id == user.id).order_by(Organization.name).all())


def switch(db: Session, user: User, org_id: int) -> bool:
    m = membership(db, user.id, org_id)
    if not m:
        return False
    user.org_id, user.role, user.can_sign = org_id, m.role, m.can_sign
    return True


def role_in(db: Session, user: User, org_id: int) -> str | None:
    """A user's role in an organization, for checks on someone who may be working in another one."""
    m = membership(db, user.id, org_id)
    return m.role if m else None
