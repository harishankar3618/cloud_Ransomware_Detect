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
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            z-index: 0;
        }

        .main-container {
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 20px;
            width: 100%;
            max-width: 1200px;
            z-index: 1;
        }

        .container {
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 20px;
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            padding: 35px;
            border-radius: 15px;
            box-shadow: 0 8px 20px rgba(0, 0, 0, 0.5);
            width: 100%;
            max-width: 500px;
            text-align: center;
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
            opacity: 0.6;
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
            backdrop-filter: blur(10px);
            border: 1px solid #00ffcc;
            border-radius: 15px;
            padding: 20px;
            width: 100%;
            max-width: 800px;
            box-shadow: 0 8px 20px rgba(0, 0, 0, 0.5);
            animation: slideIn 0.5s ease;
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
            margin-bottom: 10px;
            font-size: 1.1rem;
        }

        .result-item pre {
            font-size: 0.9rem;
            background: rgba(0, 0, 0, 0.3);
            padding: 10px;
            border-radius: 5px;
            overflow-x: auto;
            white-space: pre-wrap;
            word-wrap: break-word;
            color: #fff;
            border: 1px solid rgba(255, 255, 255, 0.1);
        }

        .alert {
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            text-align: center;
        }

        .alert-success {
            background: rgba(0, 255, 0, 0.1);
            border: 1px solid #00ff00;
            color: #00ff00;
        }

        .alert-error {
            background: rgba(255, 0, 0, 0.1);
            border: 1px solid #ff0000;
            color: #ff0000;
        }

        .loading {
            display: none;
            text-align: center;
            color: #00ffcc;
            margin-top: 10px;
        }

        .loading i {
            animation: spin 1s linear infinite;
        }

        @keyframes slideIn {
            from {
                opacity: 0;
                transform: translateY(-20px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        @media (max-width: 600px) {
            .container {
                padding: 20px;
                width: 95%;
            }

            input[type="file"], input[type="email"] {
                font-size: 0.9rem;
            }

            .result-container {
                width: 95%;
            }
        }
    </style>
</head>
<body>
    <div id="particles-js"></div>
    <div class="main-container">
        <div class="container">
            <div class="form-container">
                <img src="logo.png" alt="Ransomewatch Logo" class="logo">
                <h1>Ransomewatch</h1>
                <p style="color: #777; margin-bottom: 1rem;">Check your files for potential malware threats easily.</p>
                
                @if(isset($success) && $success)
                    <div class="alert alert-success">
                        <i class="fas fa-check-circle"></i>
                        {{ $message }}
                    </div>
                @endif

                @if(isset($error))
                    <div class="alert alert-error">
                        <i class="fas fa-exclamation-triangle"></i>
                        {{ $error }}
                    </div>
                @endif

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
                    <button type="submit" id="submitBtn">Check File</button>
                    
                    <div class="loading" id="loading">
                        <i class="fas fa-spinner"></i>
                        <p>Scanning files, please wait...</p>
                    </div>
                </form>
            </div>
        </div>

        <!-- Result Section -->
        @if(isset($results) && count($results) > 0)
            <div class="result-container">
                <h2><i class="fas fa-shield-alt"></i> Malware Scan Results</h2>
                @foreach($results as $result)
                    <div class="result-item">
                        <h3><i class="fas fa-file"></i> {{ $result['file'] }}</h3>
                        <pre>{{ $result['output'] }}</pre>
                    </div>
                @endforeach
            </div>
        @endif

        <!-- IP Results Section -->
        @if(isset($ipResults))
            <div class="result-container">
                <h2><i class="fas fa-network-wired"></i> IP Scan Results</h2>
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
                shape: {
                    type: "circle",
                }
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

        // JavaScript to handle radio button changes
        document.getElementById('fileRadio').addEventListener('change', function() {
            if (this.checked) {
                document.getElementById('fileInputContainer').style.display = 'block';
                document.getElementById('folderInputContainer').style.display = 'none';
                document.getElementById('upload').required = true;
                document.getElementById('uploadFolder').required = false;
                document.getElementById('uploadFolder').removeAttribute('required');
            }
        });

        document.getElementById('folderRadio').addEventListener('change', function() {
            if (this.checked) {
                document.getElementById('fileInputContainer').style.display = 'none';
                document.getElementById('folderInputContainer').style.display = 'block';
                document.getElementById('upload').required = false;
                document.getElementById('upload').removeAttribute('required');
                document.getElementById('uploadFolder').required = true;
            }
        });

        // Handle form submission with validation
        document.getElementById('malwareForm').addEventListener('submit', function(e) {
            const fileRadio = document.getElementById('fileRadio');
            const folderRadio = document.getElementById('folderRadio');
            const fileInput = document.getElementById('upload');
            const folderInput = document.getElementById('uploadFolder');
            const emailInput = document.getElementById('emailInput');
            
            // Custom validation
            let isValid = true;
            let errorMessage = '';
            
            // Check email
            if (!emailInput.value || !emailInput.checkValidity()) {
                isValid = false;
                errorMessage = 'Please enter a valid email address.';
            }
            
            // Check file/folder selection
            if (fileRadio.checked && (!fileInput.files || fileInput.files.length === 0)) {
                isValid = false;
                errorMessage = 'Please select a file to scan.';
            } else if (folderRadio.checked && (!folderInput.files || folderInput.files.length === 0)) {
                isValid = false;
                errorMessage = 'Please select a folder to scan.';
            }
            
            if (!isValid) {
                e.preventDefault();
                alert(errorMessage);
                return false;
            }
            
            // Show loading state
            const submitBtn = document.getElementById('submitBtn');
            const loading = document.getElementById('loading');
            
            submitBtn.disabled = true;
            submitBtn.textContent = 'Scanning...';
            loading.style.display = 'block';
            
            return true;
        });
    </script>
</body>
</html>