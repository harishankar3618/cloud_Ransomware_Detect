<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Ransomewatch</title>
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
            background: linear-gradient(135deg, #ff7eb3, #ff758c, #ff9470);
            color: #333;
        }

        .container {
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 20px;
            background: linear-gradient(135deg, #ffffff, #f0f0f0);
            padding: 35px; /* Increased padding for a more spacious layout */
            border-radius: 15px;
            box-shadow: 0 8px 20px rgba(0, 0, 0, 0.1);
            width: 95%; /* Slightly increased width */
            max-width: 500px; /* Increased max width for a larger container */
            text-align: center;
            position: relative;
        }

        .display{
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 20px;
        }

        h1 {
            font-size: 2rem;
            color: #ff6f61;
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
            border-color: #ff6f61;
        }

        button {
            width: 100%;
            padding: 12px;
            background: linear-gradient(135deg, #ff6f61, #ff9068);
            border: none;
            color: white;
            border-radius: 8px;
            cursor: pointer;
            font-size: 1rem;
            transition: background 0.3s ease;
        }

        button:hover {
            background: linear-gradient(135deg, #ff9068, #ff6f61);
        }

        .result-container {
            margin-top: 20px;
            padding: 15px;
            background: #f9f9f9;
            border-radius: 10px;
            text-align: left;
            font-size: 0.9em;
            color: #555;
            display: none; /* Hidden by default */
        }

        .result-container.visible {
            display: block; /* Shown when there are results */
        }

        .result-container h2 {
            font-size: 1.2rem;
            margin-bottom: 10px;
            color: #333;
        }

        .result-container pre {
            background: #f4f4f4;
            padding: 10px;
            border-radius: 8px;
            overflow-x: auto;
        }
    </style>
</head>
<body>
    <div class="display">
        <div class="container">
        <h1>Ransomewatch</h1>
        <p style="color: #777; margin-bottom: 1rem;">
            A modern and innovative tool to check your files for malware threats.
        </p>
        <form id="malwareForm" action="{{ route('malware.detect') }}" method="POST" enctype="multipart/form-data">
            @csrf
            <input type="file" id="fileInput" name="files[]" multiple>
            <input type="email" id="emailInput" name="receipt_email" placeholder="Enter receipt email" required>
            <button type="submit">Check Files</button>
        </form>
        </div>

        <!-- Result Section -->
        @if(isset($result))
            <div class="result-container visible">
                @if(!empty($results))
                    @foreach($results as $result)
                        <p>File: {{ $result['file'] }}</p>
                        <pre>{{ $result['output'] }}</pre>
                    @endforeach
                @endif
            </div>
        @endif
    </div>
</body>
</html>
