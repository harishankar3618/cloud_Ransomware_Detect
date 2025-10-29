<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Ransomewatch</title>
    <link rel="icon" href="favicon.ico" type="image/x-icon">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.3/css/all.min.css">
    <link href="https://fonts.googleapis.com/css2?family=Russo+One&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/particles.js"></script>
    <style>
        /* Global Reset */
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Russo One', sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            background: linear-gradient(35deg, #013a2e, #0e0e0e);
            color: #fff;
            position: relative;
            overflow-x: hidden;
            padding: 20px;
        }

        #particles-js {
            position: fixed;
            width: 100%;
            height: 100%;
            z-index: 0;
            top: 0;
            left: 0;
        }

        .main-container {
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 30px;
            width: 100%;
            max-width: 800px;
            z-index: 1;
            position: relative;
        }

        .container {
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            padding: 35px;
            border-radius: 15px;
            box-shadow: 0 8px 20px rgba(0, 0, 0, 0.5);
            width: 100%;
            max-width: 500px;
            text-align: center;
            border: 1px solid rgba(0, 255, 204, 0.2);
        }

        .container h1 {
            font-size: 2rem;
            margin-bottom: 10px;
            color: #00ffcc;
        }

        input[type="file"], input[type="email"] {
            width: 100%;
            padding: 12px 15px;
            margin-bottom: 15px;
            border: 1px solid #00ffcc;
            border-radius: 8px;
            font-size: 1rem;
            transition: 0.3s ease;
            background: rgba(255, 255, 255, 0.2);
            color: #fff;
        }

        input[type="file"]:hover, input[type="email"]:hover {
            border-color: #138673;
        }

        input::placeholder {
            color: rgba(255, 255, 255, 0.7);
        }

        button {
            width: 100%;
            padding: 12px;
            background: linear-gradient(135deg, #00ffcc, #019c82);
            border: none;
            color: white;
            border-radius: 8px;
            cursor: pointer;
            font-size: 1rem;
            transition: all 0.3s ease;
        }

        button:hover {
            background: linear-gradient(135deg, #138673, #0d5a4d);
            transform: scale(1.05);
        }

        button:disabled {
            background: #666;
            cursor: not-allowed;
            transform: none;
        }

        label {
            font-size: 0.95rem;
            color: #00ffcc;
            margin-bottom: 5px;
            display: block;
        }

        .logo {
            width: 120px;
            height: auto;
            margin-bottom: 10px;
        }

        .file-radio, .folder-radio {
            margin: 5px 15px 10px 0;
        }

        .result-container {
            background: rgba(255, 255, 255, 0.1);
            border: 1px solid rgba(0, 255, 204, 0.2);
            border-radius: 15px;
            padding: 20px;
            width: 100%;
            max-width: 700px;
            box-shadow: 0 8px 20px rgba(0, 0, 0, 0.5);
            backdrop-filter: blur(10px);
        }

        .result-container h2 {
            font-size: 1.5rem;
            color: #00ffcc;
            margin-bottom: 15px;
            text-align: center;
        }

        .result-item {
            background: rgba(255, 255, 255, 0.05);
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 15px;
            border-left: 4px solid #00ffcc;
        }

        .result-item h3 {
            color: #00ffcc;
            font-size: 1.1rem;
            margin-bottom: 10px;
        }

        .result-item pre {
            font-size: 0.9rem;
            background: rgba(0, 0, 0, 0.3);
            padding: 12px;
            border-radius: 5px;
            overflow-x: auto;
            white-space: pre-wrap;
            word-wrap: break-word;
            color: #fff;
            max-height: 300px;
            overflow-y: auto;
        }

        .alert {
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            font-size: 1rem;
        }

        .alert-success {
            background: rgba(0, 255, 204, 0.1);
            border: 1px solid #00ffcc;
            color: #00ffcc;
        }

        .alert-error {
            background: rgba(255, 0, 0, 0.1);
            border: 1px solid #ff4444;
            color: #ff4444;
        }

        .loading {
            display: none;
            color: #00ffcc;
            margin-top: 10px;
        }

        .loading.show {
            display: block;
        }

        .no-results {
            text-align: center;
            color: #888;
            font-style: italic;
            padding: 20px;
        }

        @media (max-width: 600px) {
            .container {
                padding: 20px;
                width: 90%;
            }

            input[type="file"], input[type="email"] {
                font-size: 0.9rem;
            }

            .result-container {
                width: 90%;
            }
        }
        #folderInputContainer, #fileInputContainer {
            position: relative;
        }

        #folderInputContainer.hidden,
        #fileInputContainer.hidden {
            opacity: 0;
            position: absolute;
            height: 0;
            overflow: hidden;
            pointer-events: none;
        }
    </style>
</head>
<body>
    <div id="particles-js"></div>
    <div class="main-container">
        <div class="container">
            <div class="form-container">
                <h1>Ransomewatch</h1>
                <p style="color: #777; margin-bottom: 1rem;">Check your files for potential malware threats easily.</p>

                @if(session('success'))
                    <div class="alert alert-success">{{ session('success') }}</div>
                @endif

                @if(session('error'))
                    <div class="alert alert-error">{{ session('error') }}</div>
                @endif

                @if ($errors->any())
                    <div class="alert alert-error">
                        <ul style="margin: 0; padding-left: 20px;">
                            @foreach ($errors->all() as $error)
                                <li>{{ $error }}</li>
                            @endforeach
                        </ul>
                    </div>
                @endif

                <form id="malwareForm" action="{{ route('malware.detect') }}" method="POST" enctype="multipart/form-data">
                    @csrf

                    <label for="uploadType">Choose Upload Type:</label><br>
                    <label class="file-radio">
                        <input type="radio" name="fileOrFolder" value="file" id="fileRadio" checked> File
                    </label>
                    <label class="folder-radio">
                        <input type="radio" name="fileOrFolder" value="folder" id="folderRadio"> Folder
                    </label>

                    <div id="fileInputContainer">
                        <input type="file" name="uploads[]" id="upload" accept="*">
                    </div>

                    <div id="folderInputContainer" class="hidden">
                        <input type="file" name="uploads[]" id="uploadFolder" webkitdirectory multiple>
                    </div>

                    <input type="email" id="emailInput" name="receipt_email" placeholder="Enter receipt email" 
                           value="{{ old('receipt_email') }}" required>

                    <button type="submit" id="submitBtn">Check File</button>

                    <div class="loading" id="loadingMessage">
                        <i class="fas fa-spinner fa-spin"></i> Scanning files, please wait...
                    </div>
                </form>
            </div>
        </div>

        @if(isset($results) && is_array($results) && count($results) > 0)
            <div class="result-container">
                <h2>Malware Scan Results</h2>
                @foreach($results as $result)
                    <div class="result-item">
                        <h3>{{ $result['file'] ?? 'Unknown File' }}</h3>
                        @if(isset($result['output']) && !empty(trim($result['output'])))
                            <pre>{{ $result['output'] }}</pre>
                        @else
                            <p style="color: #888;">No scan output available or file is clean</p>
                        @endif
                        @if(isset($result['error']) && !empty($result['error']))
                            <div style="color: #ff4444; margin-top: 10px;">
                                <strong>Error:</strong>
                                <pre style="background: rgba(255, 0, 0, 0.1);">{{ $result['error'] }}</pre>
                            </div>
                        @endif
                    </div>
                @endforeach
            </div>
        @elseif(isset($scan_completed) && $scan_completed)
            <div class="result-container">
                <div class="no-results">
                    No results to display. This might indicate that the scan completed but no malware was detected.
                </div>
            </div>
        @endif

        @if(isset($ipResults) && !empty($ipResults))
            <div class="result-container">
                <h2>IP Scan Results</h2>
                <div class="result-item">
                    <pre>{{ json_encode($ipResults, JSON_PRETTY_PRINT) }}</pre>
                </div>
            </div>
        @endif
    </div>

    <script>
        particlesJS("particles-js", {
            particles: {
                number: { value: 100 },
                size: { value: 3 },
                move: { enable: true, speed: 1 },
                line_linked: {
                    enable: true,
                    distance: 150,
                    color: "#00ffcc",
                    opacity: 0.4,
                    width: 1
                },
                shape: { type: "circle" }
            },
            interactivity: {
                events: {
                    onhover: { enable: true, mode: "repulse" },
                    onclick: { enable: true, mode: "push" },
                    resize: true
                },
                modes: {
                    grab: { distance: 400, line_linked: { opacity: 1 } },
                    bubble: { distance: 400, size: 40, duration: 2, opacity: 8, speed: 3 },
                    repulse: { distance: 200, duration: 0.4 },
                    push: { particles_nb: 4 },
                    remove: { particles_nb: 2 }
                }
            },
            retina_detect: true
        });

        const fileRadio = document.getElementById('fileRadio');
        const folderRadio = document.getElementById('folderRadio');
        const fileInputContainer = document.getElementById('fileInputContainer');
        const folderInputContainer = document.getElementById('folderInputContainer');

        fileRadio.addEventListener('change', function () {
            if (this.checked) {
                fileInputContainer.classList.remove('hidden');
                folderInputContainer.classList.add('hidden');
            }
        });

        folderRadio.addEventListener('change', function () {
            if (this.checked) {
                folderInputContainer.classList.remove('hidden');
                fileInputContainer.classList.add('hidden');
            }
        });

        document.getElementById('malwareForm').addEventListener('submit', function (e) {
            const isFile = fileRadio.checked;
            const fileInput = document.getElementById('upload');
            const folderInput = document.getElementById('uploadFolder');

            const selectedFiles = isFile ? fileInput.files : folderInput.files;

            if (!selectedFiles.length) {
                alert("Please select at least one file or folder.");
                e.preventDefault();
                return;
            }

            document.getElementById('submitBtn').disabled = true;
            document.getElementById('submitBtn').textContent = 'Scanning...';
            document.getElementById('loadingMessage').classList.add('show');
        });
    </script>
</body>
</html>
