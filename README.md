# ari-web server -- <https://server.ari-web.xyz/>

> random stuff for me to do

## comments api

-   POST / -- post a comment
    -   data : `author`, `content`
-   GET /\<from\>/\<to\> -- get comments with IDs in range of from to to
-   GET /total -- total comments count
-   POST /censor -- censor a comment ( localhost only )
    -   data : `id`, `reason`
