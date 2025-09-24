include "page.wl"

let posts = $query("SELECT P.id, P.title, P.is_link, P.content, (SELECT COUNT(*) FROM Comments as C WHERE c.parent_post=P.id) as num_comments, CURRENT_TIMESTAMP as date FROM Posts as P")

if posts == none:
    posts = []

let style = 
    <style>
        .item {
            overflow: auto;
            border-bottom: 1px solid #E8D4A9;
            font-size: 14px;
        }
        .item:last-child {
            border-bottom: 0;
        }
        .item span {
            color: #7A5F2A;
            text-decoration: none;
        }
        .item div {
            color: #E8D4A9;
            float: left
        }
        .item div:first-child {
            width: calc(100% - 250px);
        }
        .item div:last-child {
            width: 250px;
            text-align: right;
        }

        #no-posts {
            margin: 60px auto;
            width: 100%;
            text-align: center;
            color: #7A5F2A;
        }
    </style>

let main =
    <main>

        \if len(posts) == 0:
            <div id="no-posts">There are no posts yet!</div>

        \for post in posts: {

            let link
            if post.is_link != 0:
                link = post.content
            else
                link = ["/post?id=", post.id]

            <div class="item">
                <div>
                    <a href=\'"'\link\'"'>\escape(post.title)</a>
                </div>
                <div>
                    <span>\escape(post.date)</span> | <span>\escape(post.num_comments) comments</span>
                </div>
            </div>
        }
    </main>

page("Index", $login_user_id, style, main)