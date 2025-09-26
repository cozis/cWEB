let style = 
    <style>

        span {
            text-align: center;
            color: #1D2B42;
            font-size: 18px;
            display: inline-block;
            width: 100%;
            margin-top: 30px;
        }

        form {
            max-width: 300px;
            margin: 30px auto;
        }

        form input {
            border: 0;
            outline: 0;
            width: 100%;
            border-radius: 3px;
            padding: 8px;
            margin-bottom: 15px;
        }

        form input[type=text],
        form input[type=email],
        form input[type=password] {
            background: #E8D4A9;
            border: 1px solid #D4C298;
        }

        form input[type=text]:focus,
        form input[type=email]:focus,
        form input[type=password]:focus {
            border-color: #5780C9;
            background: #fff;
        }

        form input[type=submit] {
            cursor: pointer;
            background: #5780C9;
            color: #F7E6C0;
        }

        form input[type=submit]:hover {
            background: #1D2B42;
        }

        .form-links {
            text-align: center;
            font-size: 12px;
        }
        .form-links a {
            color: #7A5F2A;
            margin: 0 10px;
        }
        .form-links a:hover {
            color: #1D2B42;
        }

        #response {
            max-width: 300px;
            margin: auto;
        }
        #response .error {
            margin-top: 30px;
            border-radius: 3px;
            border: 1px solid #E44C82;
            background: #F295B5;
            padding: 5px 10px;
        }
    </style>