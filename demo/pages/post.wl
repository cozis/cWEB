include "page.wl"

let post_id = $args(0)
let posts = $query("SELECT U.username, P.title, P.content FROM Posts as P, Users as U WHERE P.id=? AND U.id=P.author", post_id)
let comments = $query("SELECT C.id, U.username, C.content, C.parent_post, C.parent_comment FROM Comments as C, Users as U WHERE C.parent_post=? AND U.id=C.author", post_id)

let lookup = {}

for comment in comments: {
    comment.child = []
    lookup[comment.id] = comment
}

let root_comments = []

for comment in comments: {
    if comment.parent_comment == none:
        root_comments << comment
    else
        lookup[comment.parent_comment].child << comment
}

let post = posts[0]

let style =
    <style>
    .thread-header {
        padding: 15px 0;
        border-bottom: 2px solid #E8D4A9;
        margin-bottom: 20px;
    }
    .thread-title {
        font-size: 16px;
        font-weight: bold;
        margin-bottom: 8px;
    }
    .thread-title a {
        color: #1D2B42;
        text-decoration: none;
    }
    .thread-title a:hover {
        text-decoration: underline;
    }
    .thread-meta {
        font-size: 12px;
        color: #7A5F2A;
        margin-bottom: 10px;
    }
    .thread-meta a {
        color: #7A5F2A;
    }
    .thread-text {
        font-size: 14px;
        color: #1D2B42;
        line-height: 160%;
        margin-bottom: 10px;
    }
    .thread-actions {
        font-size: 12px;
    }
    .thread-actions a {
        color: #7A5F2A;
        margin-right: 10px;
    }
    
    /* Comment styles */
    .comment {
        margin-bottom: 15px;
        border-left: 1px solid #E8D4A9;
        padding-left: 10px;
    }
    
    .comment-meta {
        font-size: 11px;
        color: #7A5F2A;
        margin-bottom: 5px;
    }
    .comment-meta a {
        color: #7A5F2A;
    }
    .comment-text {
        font-size: 13px;
        color: #1D2B42;
        line-height: 150%;
        margin-bottom: 5px;
    }
    .comment-actions {
        font-size: 11px;
    }
    .comment-actions a {
        color: #7A5F2A;
        margin-right: 8px;
    }
    .comment-actions a:hover {
        color: #1D2B42;
    }
    
    .vote-buttons {
        float: left;
        width: 15px;
        margin-right: 8px;
        font-size: 10px;
        text-align: center;
    }
    .vote-buttons a {
        display: block;
        color: #7A5F2A;
        text-decoration: none;
        line-height: 100%;
    }
    .vote-buttons a:hover {
        color: #1D2B42;
    }
    .comment-content {
        margin-left: 23px;
    }
    .comment-child {
        margin-top: 10px;
        margin-left: 10px;
    }
    .add-comment {
    }
    .add-comment form {
        margin: 0;
        overflow: auto;
    }
    .add-comment form textarea {
        width: 100%;
        height: 80px;
        font-family: monospace;
        font-size: 12px;
        background: white;
        border: 1px solid #D4C298;
        border-radius: 3px;
        padding: 8px;
        box-sizing: border-box;
        resize: vertical;
    }
    .add-comment form input[type=submit] {
        background: #5780C9;
        color: white;
        border: none;
        border-radius: 3px;
        padding: 6px 12px;
        font-family: monospace;
        font-size: 12px;
        cursor: pointer;
        margin-top: 8px;
        float: right;
    }
    .add-comment input[type=submit]:hover {
        background: #1D2B42;
    }
    summary {
        list-style: none;
        text-decoration: underline;
        color: #7A5F2A;
        cursor: pointer;
    }
    ::-webkit-details-marker {
        display: none;
    }

    #no-comments {
        margin: 30px 0;
        width: 100%;
        text-align: center;
        color: #7A5F2A;
    }
    pre {
        white-space: pre-wrap;       /* Since CSS 2.1 */
        white-space: -moz-pre-wrap;  /* Mozilla, since 1999 */
        white-space: -pre-wrap;      /* Opera 4-6 */
        white-space: -o-pre-wrap;    /* Opera 7 */
        word-wrap: break-word;       /* Internet Explorer 5.5+ */
    }
    </style>

let main =
    <main>
        <div class="thread-header">
            <div class="thread-title">
                <span>\{escape post.title}</span>
            </div>
            <div class="thread-meta">
                submitted 3 hours ago by <a href="">\{escape post.username}</a> | <a href="">\{len comments}</a>
            </div>
            <div class="thread-text">
                <pre>\{escape post.content}</pre>
            </div>
            <details>
                <summary>
                    reply
                </summary>
                <div class="add-comment">
                    <form action="/api/comment" method="POST">
                        <input type="hidden" name="csrf"        value="\{$csrf}" />
                        <input type="hidden" name="parent_post" value="\{post_id}" />
                        <textarea name="content" placeholder="Add a comment..."></textarea>
                        <input type="submit" vaue="Publish" />
                    </form>
                </div>
            </details>
        </div>
        \if len(root_comments) == 0:
            <div id="no-comments">
                No comments
            </div>
        else for comment in root_comments:
            render_comment(post_id, comment)
    </main>

procedure render_comment(post_id, comment) {
    <div class="comment">
        <div class="vote-buttons">
            <a href="">▲</a>
            <a href="">▼</a>
        </div>
        <div class="comment-content">
            <div class="comment-meta">
                <a href="">\{escape comment.username}</a> 2 hours ago
            </div>
            <div class="comment-text">
                <pre>\{escape comment.content}</pre>
            </div>
            \if $login_user_id != none:
                <details>
                    <summary>
                        reply
                    </summary>
                    <div class="add-comment">
                        <form action="/api/comment" method="POST">
                            <input type="hidden" name="csrf"           value="\{$csrf}" />
                            <input type="hidden" name="parent_post"    value="\{post_id}" />
                            <input type="hidden" name="parent_comment" value="\{comment.id}" />
                            <textarea name="content" placeholder="Add a comment..."></textarea>
                            <input type="submit" vaue="Publish" />
                        </form>
                    </div>
                </details>
        </div>
        <div class="comment-child">
        \for child in comment.child:
            render_comment(post_id, child)
        </div>
    </div>
}

page(post.title, $login_user_id, style, main)