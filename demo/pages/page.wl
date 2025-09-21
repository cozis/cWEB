
procedure page(title, login_user_id, style, main)
    <html>
    <head>
        <meta charset="UTF-8" />
        <title>CN - \escape(title)</title>
        <style>
            body {
                line-height: 200%;
                font-family: monospace;
                max-width: 800px;
                margin: 20px auto;
            }
            nav {
                overflow: auto;
                background: #5780C9;
                color: #6E93D4;
                padding: 5px 10px;
                border-top-left-radius: 3px;
                border-top-right-radius: 3px;
            }
            nav div {
                float: left
            }
            nav div:last-child {
                float: right
            }
            nav a {
                font-size: 14px;
                color: #1D2B42;
            }
            nav a.current {
                font-weight: bold;
            }
            main {
                padding: 5px 10px;
                background: #F7E6C0;
                border-bottom-left-radius: 3px;
                border-bottom-right-radius: 3px;
            }
            footer {
                padding: 5px 10px;
            }
        </style>
        \(style)
        <script src="https://cdnjs.cloudflare.com/ajax/libs/htmx/1.9.2/htmx.min.js"></script>
    </head>
    <body>
        <nav>
            <div>
                <a href="/index">index</a>
                \if login_user_id != none: {
                    "|\n"
                    <a href="/write">write</a>
                }
            </div>
            \if login_user_id == none:
                <div>
                    <a href="/login">log-in</a>
                    |
                    <a href="/signup">sign-up</a>
                </div>
            else
                <div>
                    <a href="">settings</a>
                    |
                    <a href="/api/logout">log-out</a>
                </div>
        </nav>
        \main
        <footer>
            Made with love by cozis
        </footer>
    </body>
    </html>
