<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RansomeWatch - File Malware Scanner</title>
    <style>
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            font-family: Arial, sans-serif;
            background: linear-gradient(to bottom right, #007BFF, #0056b3);
            color: #333;
        }

        .container {
            background: #fff;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 4px 10px rgba(0, 0, 0, 0.15);
            text-align: center;
            width: 90%;
            max-width: 400px;
        }

        .container h1 {
            font-size: 1.8em;
            margin-bottom: 15px;
            color: #007BFF;
        }

        .container p {
            font-size: 0.9em;
            margin-bottom: 20px;
            color: #555;
        }

        input[type="file"],
        input[type="email"] {
            width: 100%;
            padding: 12px;
            margin-bottom: 15px;
            border: 1px solid #ccc;
            border-radius: 5px;
            font-size: 1em;
            background: #f9f9f9;
        }

        input:focus {
            border-color: #007BFF;
            outline: none;
        }

        button {
            width: 100%;
            padding: 12px;
            background-color: #007BFF;
            border: none;
            color: white;
            border-radius: 5px;
            cursor: pointer;
            font-size: 1.1em;
            transition: background-color 0.3s ease;
        }

        button:hover {
            background-color: #0056b3;
        }

        .result {
            margin-top: 20px;
            padding: 15px;
            background: #e9ecef;
            border-radius: 5px;
            text-align: left;
            font-size: 0.95em;
            color: #333;
            word-wrap: break-word;
        }

        .result h2 {
            margin-bottom: 10px;
            font-size: 1.2em;
            color: #333;
        }

        @media (max-width: 600px) {
            body {
                padding: 10px;
            }

            .container {
                padding: 20px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>RansomeWatch</h1>
        <p>Upload your file to check for malware and receive the results via email.</p>
        <form id="malwareForm" action="{{ route('malware.detect') }}" method="POST" enctype="multipart/form-data">
            @csrf
            <input type="file" id="fileInput" name="file" required>
            <input type="email" id="emailInput" name="receipt_email" placeholder="Enter your email" required>
            <button type="submit">Scan File</button>
        </form>
    </div>

    <div class="result-container">
        @if(isset($result))
            <div class="result">
                <h2>Malware Scan Result</h2>
                <pre>{{ $result }}</pre>
            </div>
        @endif
        @if(isset($error))
            <div class="result">
                <h2>Scan Error</h2>
                <pre>{{ $error }}</pre>
            </div>
        @endif
    </div>
</body>
</html>
