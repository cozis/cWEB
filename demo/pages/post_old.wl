include "page.wl"

let posts = $query("SELECT title, content FROM Posts WHERE id=?", $post_id)
let comments = $query("SELECT C.id, U.username, C.content, C.parent_post, C.parent_comment FROM Comments as C, Users as U WHERE C.parent_post=? AND U.id == C.author", $post_id)

let lookup = {}

for comment in comments: {
    comment.child = []
    lookup[comment.id] = comment
}

let roots = []

for comment in comments: {
    if comment.parent_comment == none:
        roots << comment
    else
        lookup[comment.parent_comment].child << comment
}

comments = roots

let post = posts[0]

let style =
    <style>
    .child {
        border-left: 3px solid #ccc;
        padding-left: 10px;
    }
    form textarea {
        width: 100%;
    }
    </style>

procedure render_comment(parent)
    <div>
        <a href="">\parent.username</a>
        <p>
            \parent.content
        </p>
        <div class="child">
            \if $login_user_id != none:
                <form action="/api/comment" method="POST">
                    <input type="hidden" name="parent_post"    value=\'"'\$post_id\'"' />
                    <input type="hidden" name="parent_comment" value=\'"'\parent.id\'"' />
                    <textarea name="content"></textarea>
                    <input type="submit" vaue="Publish" />
                </form>
            \for child in parent.child:
                render_comment(child)
        </div>
    </div>

let main =
    <main>
        <h3>\post.title</h3>
        <p>\post.content</p>
        <div>
            <form action="/api/comment" method="POST">
                <input type="hidden" name="parent_post" value=\'"'\$post_id\'"' />
                <textarea name="content"></textarea>
                <input type="submit" vaue="Publish" />
            </form>
        </div>
        \if len comments == 0:
            <span>No comments yet!</span>
        else for comment in comments:
            render_comment(comment)
    </main>

page(post.title, $login_user_id, style, main)