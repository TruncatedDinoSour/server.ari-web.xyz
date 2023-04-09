# ari-web server -- <https://server.ari-web.xyz/>

> random stuff for me to do

## api key

api key is stored in a file on the server called `pw`, same
directory as the app is working in, per average the default
key will be secure enough, although you are free to change it,
change the file, **_restart the app when you change the api key_**

## comments api

-   POST / -- post a comment
    -   data : `author`, `content`
-   GET /\<from\>/\<to\> -- get comments with IDs in range of from to to
-   GET /total -- total comments count
-   POST /ban -- ban an author of a comment ( requires `api-key` header )
    -   data : `id`
-   POST /sql -- run sql queries ( requires `api-key` header )
    -   data : `sql`
