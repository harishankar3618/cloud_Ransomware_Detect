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
            padding: 35px;
            border-radius: 15px;
            box-shadow: 0 8px 20px rgba(0, 0, 0, 0.1);
            width: 95%;
            max-width: 500px;
            text-align: center;
            z-index: 1;

        }

        .container h1 {
            font-size: 2rem;
            margin-bottom: 10px;
            color: #555;
        }

        input[type="file"], input[type="email"] {
            width: 100%;
            padding: 12px 15px;
            margin-bottom: 15px;
            border: 1px solid #ccc;
            border-radius: 8px;
            font-size: 1rem;
            transition: 0.3s ease;
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
            transform: scale(1.05);
        }

        label {
            font-size: 0.95rem;
            color: #555;
            margin-bottom: 5px;
            display: block;
        }

        .file-radio, .folder-radio {
            margin: 5px 15px 10px 0;
        }

        .result-container {
            margin-top: 20px;
            padding: 15px;
            background: #f9f9f9;
            border: 1px solid #ddd;
            border-radius: 8px;
            max-height: 200px;
            overflow-y: auto;
            width: 100%;
            box-shadow: 0 4px 10px rgba(0, 0, 0, 0.1);
            z-index: 1;
        }

        .result-container h2 {
            font-size: 1.2rem;
            color: #444;
            margin-bottom: 10px;
        }

        .result-container ul {
            list-style: none;
            padding-left: 0;
        }

        .result-container li {
            font-size: 0.95rem;
            color: #555;
            margin-bottom: 10px;
        }

        .result-container pre {
            font-size: 0.85rem;
            background: #eee;
            padding: 10px;
            border-radius: 5px;
            overflow-x: auto;
            white-space: pre-wrap;
            word-wrap: break-word;
        }

        @media (max-width: 600px) {
            .container {
                padding: 20px;
                width: 90%;
            }

            input[type="file"], input[type="email"] {
                font-size: 0.9rem;
            }
        }
    </style>
</head>
<body>
    <div class="display">
        <div class="container">
            <h1>Ransomewatch</h1>
            <p style="color: #777; margin-bottom: 1rem;">Check your files for potential malware threats easily.</p>
            <form id="malwareForm" action="{{ route('malware.detect') }}" method="POST" enctype="multipart/form-data">
                @csrf
                <div>
                    <label for="uploadType">Choose Upload Type:</label><br>
                    <label class="file-radio">
                        <input type="radio" name="fileOrFolder" value="file" id="fileRadio" checked> File
                    </label>
                    <label class="folder-radio">
                        <input type="radio" name="fileOrFolder" value="folder" id="folderRadio"> Folder
                    </label>
                </div>

                <!-- File Upload -->
                <div id="fileInputContainer">
                    <input type="file" name="uploads[]" id="upload" accept="*" />
                </div>

                <!-- Folder Upload (Initially hidden) -->
                <div id="folderInputContainer" style="display: none;">
                    <input type="file" name="uploads[]" id="uploadFolder" webkitdirectory multiple />
                </div>

                <input type="email" id="emailInput" name="receipt_email" placeholder="Enter receipt email" required>
                <button type="submit">Check File</button>
            </form>

        </div>
        <!-- Result Section -->
        @if(isset($results))
            <div class="result-container">
                <h2>Malware Scan Results</h2>
                <ul>
                    @foreach($results as $result)
                        <li>
                            @if(isset($result['output']))
                                <pre>{{ $result['output'] }}</pre>
                            @endif
                        </li>
                    @endforeach
                </ul>
            </div>
        @endif
    </div>

    <script>
        // JavaScript to handle radio button changes
        document.getElementById('fileRadio').addEventListener('change', function() {
            if (this.checked) {
                document.getElementById('fileInputContainer').style.display = 'block';
                document.getElementById('folderInputContainer').style.display = 'none';
            }
        });

        document.getElementById('folderRadio').addEventListener('change', function() {
            if (this.checked) {
                document.getElementById('fileInputContainer').style.display = 'none';
                document.getElementById('folderInputContainer').style.display = 'block';
            }
        });
    </script>
</body>
</html>
