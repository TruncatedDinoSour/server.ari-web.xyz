#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""comments section api"""

import os
import string
import traceback
import typing
from functools import lru_cache
from hashlib import sha256
from secrets import SystemRandom
from shutil import copyfile
from urllib.parse import urlencode
from warnings import filterwarnings as filter_warnings

import sqlalchemy  # type: ignore
from flask import redirect  # type: ignore
from flask import Flask, Response, g, jsonify, request
from flask_limit import RateLimiter  # type: ignore
from sqlalchemy.orm import Session, declarative_base  # type: ignore
from werkzeug.wrappers.response import Response as WResponse

ENGINE: sqlalchemy.engine.base.Engine = sqlalchemy.create_engine(  # type: ignore
    "sqlite:///ari-web-comments.db?check_same_thread=False"
)
BASE: typing.Any = declarative_base()
SESSION: Session = sqlalchemy.orm.Session(ENGINE)  # type: ignore

MAX_CONTENT_LEN: int = 1024
MAX_AUTHOR_LEN: int = 100
MAX_APPS_ACOUNT: int = 25
MAX_FETCH_COUNT: int = 25

COMMENT_LOCK: str = ".comment-lock"

RAND: SystemRandom = SystemRandom()


def text(text: str, code: int = 200) -> Response:
    return Response(text, code, mimetype="text/plain")


@lru_cache(maxsize=512)
def hash_ip(ip: str) -> str:
    return sha256(ip.encode()).hexdigest()


class Comment(BASE):  # type: ignore
    __tablename__: str = "comments"

    cid: sqlalchemy.Column[int] = sqlalchemy.Column(
        sqlalchemy.Integer, primary_key=True
    )
    content: sqlalchemy.Column[str] = sqlalchemy.Column(
        sqlalchemy.String(MAX_CONTENT_LEN)
    )
    author: sqlalchemy.Column[str] = sqlalchemy.Column(
        sqlalchemy.String(MAX_AUTHOR_LEN)
    )
    ip: sqlalchemy.Column[str] = sqlalchemy.Column(sqlalchemy.String(68))
    admin: sqlalchemy.Column[bool] = sqlalchemy.Column(
        sqlalchemy.Boolean,
    )

    def __init__(self, content: str, author: str, admin: bool) -> None:
        self.content = content  # type: ignore
        self.author = author  # type: ignore
        self.ip = hash_ip(request.remote_addr)  # type: ignore
        self.admin = admin  # type: ignore


class Ban(BASE):  # type: ignore
    __tablename__: str = "bans"

    ip: sqlalchemy.Column[str] = sqlalchemy.Column(
        sqlalchemy.String(68),
        primary_key=True,
        unique=True,
    )

    def __init__(self, ip: str) -> None:
        self.ip = ip  # type: ignore


class IpWhitelist(BASE):  # type: ignore
    __tablename__: str = "whitelist"

    ip: sqlalchemy.Column[str] = sqlalchemy.Column(
        sqlalchemy.String(68),
        primary_key=True,
        unique=True,
    )

    author: sqlalchemy.Column[str] = sqlalchemy.Column(
        sqlalchemy.String(MAX_AUTHOR_LEN),
        unique=True,
    )

    def __init__(self, ip: str, author: str) -> None:
        self.ip = ip  # type: ignore
        self.author = author  # type: ignore


class IpQueue(BASE):  # type: ignore
    __tablename__: str = "queue"

    ip: sqlalchemy.Column[str] = sqlalchemy.Column(
        sqlalchemy.String(68),
        primary_key=True,
        unique=True,
    )

    author: sqlalchemy.Column[str] = sqlalchemy.Column(
        sqlalchemy.String(MAX_AUTHOR_LEN),
        unique=True,
    )

    content: sqlalchemy.Column[str] = sqlalchemy.Column(
        sqlalchemy.String(MAX_CONTENT_LEN),
    )

    def __init__(self, ip: str, author: str, content: str) -> None:
        self.ip = ip  # type: ignore
        self.author = author  # type: ignore
        self.content = content  # type: ignore


BASE.metadata.create_all(ENGINE)


app: Flask = Flask(__name__)

app.config.update(  # type: ignore
    {
        "RATELIMITE_LIMIT": 12,
        "RATELIMITE_PERIOD": 12,
        "SECRET_KEY": RAND.randbytes(8320),
    }
)

pw: str

if os.path.exists("pw"):
    with open("pw", "r") as f:
        pw = f.read()
else:
    with open("pw", "w") as f:
        f.write(
            (
                pw := "".join(
                    RAND.choices(
                        string.ascii_letters + string.digits + string.punctuation, k=256
                    )
                )
            )
        )


@app.before_request
@RateLimiter(app).rate_limit  # type: ignore
def limit_requests() -> typing.Union[None, Response]:
    return (
        None
        if request.headers.get("api-key") == pw
        or SESSION.query(Ban).where(Ban.ip == hash_ip(request.remote_addr)).first() is None  # type: ignore
        else text("youre banned", 403)
    )


@app.after_request  # type: ignore
def after_request(response: Response) -> Response:
    response.headers.extend(getattr(g, "headers", {}))

    response.headers.update(
        {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET,POST",
            "Access-Control-Allow-Headers": "api-key",
            "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
            "X-Frame-Options": "deny",
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "upgrade-insecure-requests",
            "X-Permitted-Cross-Domain-Policies": "none",
            "Referrer-Policy": "no-referrer",
        }
    )

    return response


@app.post("/")
def add_comment() -> Response:
    if os.path.exists(COMMENT_LOCK):
        return text("locked", 403)

    comment: typing.Dict[str, str] = request.values
    sql_obj: Comment

    content: str = comment.get("content", "").strip()[:MAX_CONTENT_LEN]

    if not content:
        return text("no valid content provided", 400)
    elif (
        whitelist := SESSION.query(IpWhitelist)  # type: ignore
        .where(IpWhitelist.ip == hash_ip(request.remote_addr))
        .first()
    ) is None:
        return text("you are not whitelisted", 401)

    SESSION.add((sql_obj := Comment(content, whitelist.author, request.headers.get("api-key") == pw)))  # type: ignore
    SESSION.commit()  # type: ignore

    return text(str(sql_obj.cid))


@app.get("/<int:cid_from>/<int:cid_to>")
def get_comments(cid_from: int, cid_to: int) -> Response:
    if abs(cid_to - cid_from) > MAX_FETCH_COUNT:
        j: Response = jsonify({})
        j.status_code = 413
        return j

    return jsonify(
        {
            c.cid: [c.author, c.content, c.admin]
            for c in SESSION.query(Comment)  # type: ignore
            .filter(Comment.cid >= cid_from, Comment.cid <= cid_to)
            .all()
        }
    )


@app.get("/total")
def total() -> Response:
    return text(str(SESSION.query(Comment.cid).count()))  # type: ignore


@app.post("/sql")
def run_sql() -> Response:
    if request.headers.get("api-key") != pw:
        return text("wrong api key", 401)
    elif "sql" not in request.values:
        return text("no sql query", 400)

    if "backup" in request.values:
        copyfile("ari-web-comments.db", request.values["backup"] + ".db")

    out: Response

    try:
        out = jsonify([tuple(row) for row in SESSION.execute(sqlalchemy.sql.text(request.values["sql"])).all()])  # type: ignore
        SESSION.commit()  # type: ignore
    except sqlalchemy.exc.ResourceClosedError:  # type: ignore
        out = jsonify([], 204)
        SESSION.commit()  # type: ignore
    except Exception:
        SESSION.rollback()  # type: ignore
        out = text(traceback.format_exc(), 500)

    return out


@app.post("/apply")
def apply() -> Response:
    content: str = request.values.get("content", "").strip()[:MAX_CONTENT_LEN]
    author: str = request.values.get("author", "").strip()[:MAX_AUTHOR_LEN]

    if not all((author, content)):
        return text("missing params", 400)
    elif SESSION.query(IpQueue.ip).count() >= MAX_APPS_ACOUNT:  # type: ignore
        return text("too many applicants at this moment try again later", 429)

    ip: str = hash_ip(request.remote_addr)

    if SESSION.query(IpWhitelist).where(IpWhitelist.ip == ip or IpWhitelist.author == author).first() is not None:  # type: ignore
        return text("already whitelisted / username is taken", 208)

    try:
        SESSION.add(  # type: ignore
            IpQueue(
                ip,
                author,
                content,
            )
        )
        SESSION.commit()  # type: ignore
    except sqlalchemy.exc.IntegrityError:  # type: ignore
        SESSION.rollback()  # type: ignore
        return text("already applied / invalid application", 400)

    return text("")


@app.get("/whoami")
def whoami() -> Response:
    if (who := SESSION.query(IpWhitelist).where(IpWhitelist.ip == hash_ip(request.remote_addr)).first()) is None:  # type: ignore
        return text("", 403)

    return text(who.author)  # type: ignore


@app.get("/lock")
def get_lock() -> Response:
    return text(str(int(os.path.exists(COMMENT_LOCK))))  # type: ignore


@app.post("/lock")
def lock() -> Response:
    if request.headers.get("api-key") != pw:
        return text("wrong api key", 401)

    clock: bool = os.path.exists(COMMENT_LOCK)

    if clock:
        os.remove(COMMENT_LOCK)
    else:
        open(COMMENT_LOCK).close()

    return text(str(int(not clock)))


@app.get("/favicon.ico")
def favicon() -> WResponse:
    return redirect("https://ari-web.xyz/favicon.ico")


@app.get("/sitemap.xml")
def sitemap() -> WResponse:
    return redirect("https://ari-web.xyz/sitemap.xml")


@app.get("/robots.txt")
def robots() -> WResponse:
    return redirect("https://ari-web.xyz/robots.txt")


@app.get("/", defaults={"path": None})
@app.get("/git", defaults={"path": None})
@app.get("/<path:path>")
@app.get("/git/<path:path>")
def git(path: typing.Optional[str]) -> WResponse:
    return redirect(
        f"https://ari-web.xyz/gh/server.ari-web.xyz/{path or ''}?{urlencode(request.args.to_dict())}"
    )


def main() -> int:
    """entry / main function"""

    app.run("0.0.0.0", debug=True)

    return 0


if __name__ == "__main__":
    assert main.__annotations__.get("return") is int, "main() should return an integer"

    filter_warnings("error", category=Warning)
    raise SystemExit(main())
