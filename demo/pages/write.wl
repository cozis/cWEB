include "page.wl"

let style =
    <style>
        form {
            max-width: 400px;
            margin: 30px auto;
        }

        form input,
        form textarea {
            border: 0;
            outline: 0;
            width: 100%;
            border-radius: 3px;
            padding: 8px;
            margin-bottom: 15px;
            background: #E8D4A9;
            border: 1px solid #D4C298;
        }

        form input:focus,
        form textarea:focus {
            border-color: #5780C9;
            background: #fff;
        }

        form textarea {
            height: 120px;
            resize: vertical;
        }

        form input[type=submit] {
            cursor: pointer;
            background: #5780C9;
            color: #F7E6C0;
        }

        form input[type=submit]:hover {
            background: #1D2B42;
        }

        .checkbox-row {
            margin-bottom: 15px;
        }

        .checkbox-row input[type="checkbox"] {
            width: auto;
            margin-right: 8px;
        }

        .checkbox-row label {
            color: #1D2B42;
            font-size: 14px;
            cursor: pointer;
        }
    </style>

let main =
    <main>
        <form action="/api/post" method="POST">

            <input type="hidden" name="csrf" value=\'"'\$csrf\'"' />
            <input type="text" id="title" name="title" placeholder="Title" required />
            
            <div class="checkbox-row">
                <input type="checkbox" id="is_link" name="is_link" onchange="togglePostType()" />
                <label>This is a link post</label>
            </div>

            <input type="url" id="url" name="link" placeholder="URL" style="display: none;" />
            
            <textarea id="content" name="content" placeholder="Write your post here..."></textarea>

            <input type="submit" value="Submit Post" />
        </form>

        <script>
            function togglePostType() {
                const checkbox = document.getElementById('is_link');
                const urlInput = document.getElementById('url');
                const contentTextarea = document.getElementById('content');
                
                if (checkbox.checked) {
                    urlInput.style.display = 'block';
                    contentTextarea.style.display = 'none';
                } else {
                    urlInput.style.display = 'none';
                    contentTextarea.style.display = 'block';
                }
            }
        </script>
    </main>

page("Write Post", $login_user_id, style, main)