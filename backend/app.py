from flask import Flask, request
from flask_cors import CORS
from flask_jwt_extended import (
    create_access_token, jwt_required, get_jwt_identity
)
from dotenv import load_dotenv

from config import Config
from extensions import db, migrate, jwt
from models import User, Ticket, AuditLog

load_dotenv()

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    CORS(app, resources={r"/api/*": {"origins": "*"}})

    db.init_app(app)
    migrate.init_app(app, db)
    jwt.init_app(app)

    # ---------- helpers ----------
    def current_user():
        uid = get_jwt_identity()
        return User.query.get(uid)

    def ticket_to_dict(t: Ticket):
        return {
            "id": t.id,
            "title": t.title,
            "description": t.description,
            "priority": t.priority,
            "status": t.status,
            "created_by": {
                "id": t.created_by.id,
                "name": t.created_by.full_name,
                "email": t.created_by.email
            },
            "assigned_to": None if not t.assigned_to else {
                "id": t.assigned_to.id,
                "name": t.assigned_to.full_name,
                "email": t.assigned_to.email
            },
            "created_at": t.created_at.isoformat(),
            "updated_at": t.updated_at.isoformat() if t.updated_at else None
        }

    def log(ticket_id: int, actor_id: int, action: str, meta: str | None = None):
        db.session.add(AuditLog(ticket_id=ticket_id, actor_id=actor_id, action=action, meta=meta))
        db.session.commit()

    # ---------- routes ----------
    @app.get("/api/health")
    def health():
        return {"status": "ok"}

    # ---- Auth ----
    @app.post("/api/auth/register")
    def register():
        data = request.get_json(force=True)
        full_name = data.get("full_name", "").strip()
        email = data.get("email", "").strip().lower()
        password = data.get("password", "")

        if not full_name or not email or not password:
            return {"error": "full_name, email, password required"}, 400

        if User.query.filter_by(email=email).first():
            return {"error": "email already registered"}, 409

        u = User(full_name=full_name, email=email, role="user")
        u.set_password(password)
        db.session.add(u)
        db.session.commit()

        token = create_access_token(identity=u.id)
        return {
            "access_token": token,
            "user": {"id": u.id, "full_name": u.full_name, "email": u.email, "role": u.role}
        }, 201

    @app.post("/api/auth/login")
    def login():
        data = request.get_json(force=True)
        email = data.get("email", "").strip().lower()
        password = data.get("password", "")

        u = User.query.filter_by(email=email).first()
        if not u or not u.check_password(password):
            return {"error": "invalid credentials"}, 401

        token = create_access_token(identity=u.id)
        return {
            "access_token": token,
            "user": {"id": u.id, "full_name": u.full_name, "email": u.email, "role": u.role}
        }

    # ---- Tickets ----
    @app.post("/api/tickets")
    @jwt_required()
    def create_ticket():
        u = current_user()
        data = request.get_json(force=True)

        title = data.get("title", "").strip()
        description = data.get("description", "").strip()
        priority = data.get("priority", "P3")

        if not title or not description:
            return {"error": "title and description required"}, 400
        if priority not in ["P1", "P2", "P3", "P4"]:
            return {"error": "invalid priority"}, 400

        t = Ticket(
            title=title,
            description=description,
            priority=priority,
            status="open",
            created_by_id=u.id
        )
        db.session.add(t)
        db.session.commit()

        log(t.id, u.id, "TICKET_CREATED", meta=f"priority={priority}")
        return {"ticket": ticket_to_dict(t)}, 201

    @app.get("/api/tickets")
    @jwt_required()
    def list_tickets():
        tickets = Ticket.query.order_by(Ticket.created_at.desc()).limit(200).all()
        return {"tickets": [ticket_to_dict(t) for t in tickets]}

    @app.get("/api/tickets/<int:ticket_id>")
    @jwt_required()
    def get_ticket(ticket_id):
        t = Ticket.query.get_or_404(ticket_id)
        return {"ticket": ticket_to_dict(t)}

    @app.patch("/api/tickets/<int:ticket_id>")
    @jwt_required()
    def update_ticket(ticket_id):
        u = current_user()
        t = Ticket.query.get_or_404(ticket_id)
        data = request.get_json(force=True)

        # basic permissions: creator or admin/engineer
        can_edit = (t.created_by_id == u.id) or (u.role in ["admin", "engineer"])
        if not can_edit:
            return {"error": "forbidden"}, 403

        allowed_status = ["open", "in_progress", "resolved", "closed"]
        allowed_priority = ["P1", "P2", "P3", "P4"]

        changed = []

        if "status" in data:
            s = data["status"]
            if s not in allowed_status:
                return {"error": "invalid status"}, 400
            t.status = s
            changed.append("status")

        if "priority" in data:
            p = data["priority"]
            if p not in allowed_priority:
                return {"error": "invalid priority"}, 400
            t.priority = p
            changed.append("priority")

        db.session.commit()
        log(t.id, u.id, "TICKET_UPDATED", meta=",".join(changed) if changed else None)

        return {"ticket": ticket_to_dict(t)}

    @app.get("/api/tickets/<int:ticket_id>/audit")
    @jwt_required()
    def ticket_audit(ticket_id):
        Ticket.query.get_or_404(ticket_id)
        logs = AuditLog.query.filter_by(ticket_id=ticket_id).order_by(AuditLog.created_at.desc()).all()

        return {
            "audit": [{
                "id": a.id,
                "action": a.action,
                "meta": a.meta,
                "actor": {
                    "id": a.actor.id,
                    "name": a.actor.full_name,
                    "email": a.actor.email,
                    "role": a.actor.role
                },
                "created_at": a.created_at.isoformat()
            } for a in logs]
        }

    return app

app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
