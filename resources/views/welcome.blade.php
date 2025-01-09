<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RansomeWatch - Modern File Scanner</title>
    <style>
        /* Global Reset */
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Poppins', sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            background: linear-gradient(135deg, #7f7fd5, #86a8e7, #91eae4);
            color: #333;
            overflow: hidden;
        }

        .container {
            display: flex;
            flex-direction: column;
            align-items: center;
            background: #fff;
            padding: 25px;
            border-radius: 15px;
            box-shadow: 0 8px 20px rgba(0, 0, 0, 0.1);
            width: 90%;
            max-width: 600px;
            position: relative;
            overflow: hidden;
        }

        .form-section {
            width: 100%;
            text-align: center;
        }

        .form-section h1 {
            font-size: 2rem;
            color: #3a77e6;
            margin-bottom: 1rem;
        }

        .form-section p {
            color: #777;
            margin-bottom: 1.5rem;
        }

        input[type="file"],
        input[type="email"] {
            width: 100%;
            padding: 12px 15px;
            margin-bottom: 15px;
            border: 1px solid #ccc;
            border-radius: 8px;
            font-size: 1rem;
            transition: 0.3s ease;
        }

        input[type="file"]:hover,
        input[type="email"]:hover {
            border-color: #3a77e6;
        }

        button {
            width: 100%;
            padding: 12px;
            background: linear-gradient(135deg, #3a77e6, #5fa9f0);
            border: none;
            color: white;
            border-radius: 8px;
            cursor: pointer;
            font-size: 1rem;
            transition: background 0.3s ease;
        }

        button:hover {
            background: linear-gradient(135deg, #5fa9f0, #3a77e6);
        }

        .result-section {
            position: absolute;
            bottom: -200px; /* Initially hidden below */
            left: 0;
            width: 100%;
            background: #f9f9f9;
            padding: 20px;
            border-radius: 15px;
            box-shadow: 0 8px 20px rgba(0, 0, 0, 0.1);
            transition: bottom 0.5s ease; /* Smooth animation */
            text-align: center;
        }

        .result-section.visible {
            bottom: 0; /* Bring it into view */
        }

        .result-section h2 {
            font-size: 1.5rem;
            color: #333;
            margin-bottom: 1rem;
        }

        .result-section pre {
            background: #e9ecef;
            padding: 15px;
            border-radius: 8px;
            font-size: 0.9rem;
            color: #555;
            white-space: pre-wrap;
            word-wrap: break-word;
            overflow: auto; /* Prevent text overflow */
            max-height: 150px; /* Limit result height */
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Form Section -->
        <div class="form-section">
            <h1>RansomeWatch</h1>
            <p>A modern tool to scan your files for malware threats.</p>
            <form id="malwareForm" action="{{ route('malware.detect') }}" method="POST" enctype="multipart/form-data">
                @csrf
                <input type="file" id="fileInput" name="file" required>
                <input type="email" id="emailInput" name="receipt_email" placeholder="Enter receipt email" required>
                <button type="button" id="scanButton">Scan File</button>
            </form>
        </div>

        <!-- Result Section -->
        <div class="result-section" id="resultSection">
            <h2>Scan Result</h2>
            <pre id="resultText">No result available yet.</pre>
        </div>
    </div>

    <script>
        // Simulating result visibility on button click
        document.getElementById('scanButton').addEventListener('click', function () {
            const resultSection = document.getElementById('resultSection');
            const resultText = document.getElementById('resultText');

            // Simulate scan process
            resultText.textContent = "Scanning complete! No threats found."; // Example text
            resultSection.classList.add('visible'); // Slide up the result box
        });
    </script>
</body>
</html>
