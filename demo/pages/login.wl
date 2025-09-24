include "page.wl"
include "login_and_signup_style.wl"

let main =
    <main>
        <span>Welcome back!</span>

        <div id="response"></div>

        <form action="/api/login" method="POST">
            <input type="text"     name="username" placeholder="username" />
            <input type="password" name="password" placeholder="password" />
            <input type="submit"   value="Log-In" />
            <div class="form-links">
                <a href="">forgot password?</a>
                |
                <a href="">create account</a>
            </div>
        </form>
    </main>

page("Log-In", none, style, main)
