#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""comments section api"""

import string
import typing
from secrets import SystemRandom
from warnings import filterwarnings as filter_warnings

import sqlalchemy  # type: ignore
from flask import (Flask, Response, g, jsonify, redirect,  # type: ignore
                   request)
from flask_limit import RateLimiter  # type: ignore
from sqlalchemy.orm import Session, declarative_base  # type: ignore
from werkzeug.wrappers.response import Response as WResponse

ENGINE: sqlalchemy.engine.base.Engine = sqlalchemy.create_engine(
    "sqlite:///ari-web-comments.db?check_same_thread=False"
)
BASE: typing.Any = declarative_base()
SESSION: Session = sqlalchemy.orm.Session(ENGINE)


class Comment(BASE):  # type: ignore
    __tablename__: str = "comments"

    cid: sqlalchemy.Column[int] = sqlalchemy.Column(
        sqlalchemy.Integer, primary_key=True
    )
    content: sqlalchemy.Column[str] = sqlalchemy.Column(sqlalchemy.String(1024))
    author: sqlalchemy.Column[str] = sqlalchemy.Column(sqlalchemy.String(100))

    def __init__(self, content: str, author: str) -> None:
        self.content = content  # type: ignore
        self.author = author  # type: ignore


BASE.metadata.create_all(ENGINE)


app: Flask = Flask(__name__)

app.config.update(  # type: ignore
    {
        "RATELIMITE_LIMIT": 15,
        "RATELIMITE_PERIOD": 10,
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
        }
    )

    return response


@app.post("/")
def add_comment() -> typing.Tuple[str, int]:
    comment: typing.Any = request.values
    sql_obj: Comment

    if not all(comment.get(k) for k in ("content", "author")):
        return "no valid comment provided", 400

    try:
        SESSION.add((sql_obj := Comment(comment["content"], comment["author"])))  # type: ignore
        SESSION.commit()
    except Exception as e:
        return f"sql error : {e}", 500

    return str(sql_obj.cid), 200


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
def total() -> str:
    return str(SESSION.query(Comment.cid).count())


@app.get("/")
def index() -> str:
    return "this is the comment section api for ari-web"


@app.get("/git")
def git() -> WResponse:
    return redirect("https://ari-web.xyz/gh/server.ari-web.xyz")


@app.get("/favicon.ico")
def favicon() -> WResponse:
    return redirect("https://ari-web.xyz/favicon.ico")


@app.get("/sitemap.xml")
def sitemap() -> WResponse:
    return redirect("https://ari-web.xyz/sitemap.xml")


@app.get("/robots.txt")
def robots() -> WResponse:
    return redirect("https://ari-web.xyz/robots.txt")


def main() -> int:
    """entry / main function"""

    app.run("0.0.0.0")

    return 0


if __name__ == "__main__":
    assert main.__annotations__.get("return") is int, "main() should return an integer"

    filter_warnings("error", category=Warning)
    raise SystemExit(main())
