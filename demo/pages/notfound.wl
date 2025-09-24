include "page.wl"

let style = 
    <style>
        .not-found-container {
            text-align: center;
            padding: 60px 20px;
        }
        .error-code {
            font-size: 72px;
            font-weight: bold;
            color: #7A5F2A;
            margin-bottom: 20px;
            line-height: 100%;
        }
        .error-message {
            font-size: 24px;
            color: #1D2B42;
            margin-bottom: 15px;
        }
        .error-description {
            font-size: 14px;
            color: #7A5F2A;
            margin-bottom: 40px;
            max-width: 500px;
            margin-left: auto;
            margin-right: auto;
            line-height: 160%;
        }

        .home-button {
            display: inline-block;
            background: #5780C9;
            color: #F7E6C0;
            padding: 12px 24px;
            text-decoration: none;
            border-radius: 5px;
            font-size: 14px;
            margin-top: 20px;
            border: none;
            cursor: pointer;
        }
        .home-button:hover {
            background: #1D2B42;
            color: #F7E6C0;
        }
    </style>

let main =
    <main>
        <div class="not-found-container">
            <div class="error-code">404</div>
            <div class="error-message">Page Not Found</div>
            <div class="error-description">
                Looks like this page wandered off somewhere.
            </div>
        </div>
    </main>

page("Not Found", $login_user_id, style, main)
