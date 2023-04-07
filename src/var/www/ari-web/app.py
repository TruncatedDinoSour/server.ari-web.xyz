#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""comments section api"""

import string
import typing
from datetime import datetime
from secrets import SystemRandom
from urllib.parse import urlencode
from warnings import filterwarnings as filter_warnings

import sqlalchemy  # type: ignore
from flask import redirect  # type: ignore
from flask import Flask, Response, g, jsonify, request
from flask_limit import RateLimiter  # type: ignore
from sqlalchemy.orm import Session, declarative_base  # type: ignore
from werkzeug.wrappers.response import Response as WResponse

ENGINE: sqlalchemy.engine.base.Engine = sqlalchemy.create_engine(
    "sqlite:///ari-web-comments.db?check_same_thread=False"
)
BASE: typing.Any = declarative_base()
SESSION: Session = sqlalchemy.orm.Session(ENGINE)  # type: ignore

MAX_CONTENT_LEN: int = 1024
MAX_AUTHOR_LEN: int = 100


def text(text: str, code: int = 200) -> Response:
    return Response(text, code, mimetype="text/plain")


def censor_text(text: str) -> str:
    return (
        hex(
            (sum(map(lambda c: (ord(c) << 1) + MAX_AUTHOR_LEN, text)) << 5)
            + MAX_CONTENT_LEN
        )
        + "f"
    )


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

    def __init__(self, content: str, author: str) -> None:
        self.content = content  # type: ignore
        self.author = author  # type: ignore


BASE.metadata.create_all(ENGINE)


app: Flask = Flask(__name__)

app.config.update(  # type: ignore
    {
        "RATELIMITE_LIMIT": 10,
        "RATELIMITE_PERIOD": 50,
        "SECRET_KEY": "".join(SystemRandom().choices(string.printable, k=8192)),
    }
)

limiter: RateLimiter = RateLimiter(app)


@app.before_request
@limiter.rate_limit  # type: ignore
def limit_requests() -> None:
    pass


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
    comment: typing.Any = request.values
    sql_obj: Comment

    content: str = comment.get("content", "").strip()[:MAX_CONTENT_LEN]
    author: str = comment.get("author", "").strip()[:MAX_AUTHOR_LEN]

    if not all((content, author)):
        return text("no valid comment provided", 400)

    SESSION.add((sql_obj := Comment(content, author)))  # type: ignore
    SESSION.commit()

    return text(str(sql_obj.cid))


@app.get("/<int:cid_from>/<int:cid_to>")
def get_comments(cid_from: int, cid_to: int) -> Response:
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
    return text(str(SESSION.query(Comment.cid).count()))


@app.route("/censor", methods=["POST"])
def censor_comment() -> typing.Tuple[str, int]:
    if (
        request.remote_addr != "127.0.0.1"
        or not request.json
        or not all(k in request.json for k in ("id", "reason"))
    ):
        return "", 400

    request.json["reason"] = request.json["reason"].strip()

    if not request.json["reason"]:
        return "", 400

    user: typing.Optional[Comment] = (  # type: ignore
        SESSION.query(Comment).where(Comment.cid == request.json["id"]).first()  # type: ignore
    )

    if user is None:
        return "", 404

    user.author = censor_text(user.author)  # type: ignore
    user.content = f"[ {censor_text(user.content)} censored on [ {datetime.utcnow()} UTC ] due to [ {request.json['reason']} ] ]"  # type: ignore

    SESSION.commit()  # type: ignore

    return "", 200


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
