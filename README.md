# ari-web server -- <https://server.ari-web.xyz/>

> random stuff for me to do

## api key

api key is stored in a file on the server called `pw`, same
directory as the app is working in, per average the default
key will be secure enough, although you are free to change it,
change the file, **_restart the app when you change the api key_**

## comments api

**none of these routes will work for you if youre ip banned and dont have the admin key to bypass the ban**

-   POST / -- post a comment ( only if youre whitelisted or are an administrator )
    -   data : `content`
-   GET /\<from\>/\<to\> -- get comments with IDs in range of from to to ( cannot request large entities, i.e. over max 25 kb ( 25 comments )
-   GET /total -- total comments count
-   POST /sql -- run sql queries ( requires `api-key` header )
    -   data : `sql` ( multiple queries, like `data={"sql": [...]}` ), `backup` ( filename )
-   POST /apply -- apply to get whitelisted and put into the IP whitelist queue
    -   data : `content`, `author` ( reason and the username tied to you IP address )
-   GET /whoami -- get your username
-   POST /lock -- lock comments section ( needs `api-key` header )
-   GET /lock -- get lock status ( 0 or 1 )
-   GET /amiadmin -- get admin status ( 0 or 1 )
-   GET /applied -- get 'if applied' status
-   POST /anon -- anonymously send a message to admins, like private feedback
    -   data : `content`

## everything else

everything else can be achieved using /sql API, for example for bans you can do like :

```sql
INSERT INTO bans (ip) VALUES ("...")
```

or to whitelist someone

```sql
SELECT * FROM queue;
-- read the output whoever you want to unban
INSERT INTO whitelist (ip, author) VALUES ("...", "some author");
DELETE FROM queue WHERE author = "some author";
```

...

see [this](https://ari-web.xyz/gh/ari-web-comments-baz)
plugin for [baz plugin manager](https://ari-web.xyz/gh/baz)
to get pre-made CLI tools
