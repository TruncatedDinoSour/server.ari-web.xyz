#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""comments section api"""

import os
import string
import sys
import traceback
import typing
from functools import lru_cache
from hashlib import sha256
from secrets import SystemRandom
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

    def __init__(self, content: str, author: str) -> None:
        self.content = content  # type: ignore
        self.author = author  # type: ignore
        self.ip = hash_ip(request.remote_addr)  # type: ignore


class Ban(BASE):  # type: ignore
    __tablename__: str = "bans"

    ip: sqlalchemy.Column[str] = sqlalchemy.Column(
        sqlalchemy.String(68),
        primary_key=True,
        unique=True,
    )

    def __init__(self, ip: str) -> None:
        self.ip = ip  # type: ignore


BASE.metadata.create_all(ENGINE)


app: Flask = Flask(__name__)

app.config.update(  # type: ignore
    {
        "RATELIMITE_LIMIT": 6,
        "RATELIMITE_PERIOD": 10,
        "SECRET_KEY": "".join(RAND.choices(string.printable, k=8192)),
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
                        string.ascii_letters + string.digits + string.punctuation, k=128
                    )
                )
            )
        )


@app.before_request
@RateLimiter(app).rate_limit  # type: ignore
def limit_requests() -> typing.Union[None, Response]:
    return (
        None
        if SESSION.query(Ban).where(Ban.ip == hash_ip(request.remote_addr)).first() is None  # type: ignore
        else text("you have been banned", 403)
        if request.headers.get("api-key") != pw
        else None
    )


@app.after_request  # type: ignore
def after_request(response: Response) -> Response:
    response.headers.extend(getattr(g, "headers", {}))

    response.headers.update(
        {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET,POST",
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
    comment: typing.Dict[str, str] = request.values
    sql_obj: Comment

    content: str = comment.get("content", "").strip()[:MAX_CONTENT_LEN]
    author: str = comment.get("author", "").strip()[:MAX_AUTHOR_LEN]

    if not all((content, author)):
        return text("no valid comment provided", 400)

    SESSION.add((sql_obj := Comment(content, author)))  # type: ignore
    SESSION.commit()  # type: ignore

    return text(str(sql_obj.cid))


@app.get("/<int:cid_from>/<int:cid_to>")
def get_comments(cid_from: int, cid_to: int) -> Response:
    if (cid_to - cid_from) > 36:
        j: Response = jsonify({})
        j.status_code = 413
        return j

    return jsonify(
        {
            c.cid: [c.author, c.content]
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

    out: typing.Tuple[str, int]

    try:
        out = str(SESSION.execute(sqlalchemy.sql.text(request.values["sql"])).all()), 200  # type: ignore
        SESSION.commit()  # type: ignore
    except sqlalchemy.exc.ResourceClosedError:  # type: ignore
        out = "", 204
        SESSION.commit()  # type: ignore
    except Exception:
        SESSION.rollback()  # type: ignore
        out = traceback.format_exc(), 500
        print(out[0], file=sys.stderr)

    return text(*out)


@app.post("/ban")
def ban() -> Response:
    if request.headers.get("api-key") != pw:
        return text("wrong api key", 401)
    elif "id" not in request.values:
        return text("no comment id", 400)

    comment: Comment = (  # type: ignore
        SESSION.query(Comment).where(Comment.cid == request.values["id"]).first()  # type: ignore
    )

    if comment is None:
        return text("no such comment", 404)
    elif not comment.ip:  # type: ignore
        return text("cannot ban the commenter", 403)

    SESSION.add(Ban(comment.ip))  # type: ignore
    SESSION.commit()  # type: ignore

    return text(str(comment.ip))  # type: ignore


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
