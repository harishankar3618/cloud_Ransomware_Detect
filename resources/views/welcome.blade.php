<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Ransomewatch</title>
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
            height: 100vh;
            background: linear-gradient(35deg, #013a2e, #0e0e0e);
            color: #fff;
            position: relative; /* Added for positioning particles */
            overflow: hidden;
        }
        #particles-js {
            position: absolute;
            width: 100%;
            height: 100%;
            z-index: 0; /* Ensure particles are behind other content */
        }
        .container {
            display: flex; /* Use flexbox for layout */
            justify-content: space-between; /* Space between form and results */
            align-items: flex-start; /* Align items to the start */
            gap: 20px; /* Gap between form and results */
            width: 100%; /* Full width */
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 20px;
            background: rgba(255, 255, 255, 0.1); /* Semi-transparent background */
            backdrop-filter: blur(10px); /* Glass effect */
            padding: 35px;
            border-radius: 15px;
            box-shadow: 0 8px 20px rgba(0, 0, 0, 0.5);
            width: 95%;
            max-width: 500px;
            text-align: center;
            z-index: 1; /* Ensure container is above particles */
        }

        .container h1 {
            font-size: 2rem;
            margin-bottom: 10px;
            color: #00ffcc; /* Neon color */
        }

        input[type="file"], input[type="email"] {
            width: 100%;
            padding: 12px 15px;
            margin-bottom: 15px;
            border: 1px solid #00ffcc; /* Neon border */
            border-radius: 8px;
            font-size: 1rem;
            transition: 0.3s ease;
            background: rgba(255, 255, 255, 0.2); /* Semi-transparent input */
            color: #fff; /* White text */
        }
        input[type="file"]:hover, input[type="email"]:hover {
            border-color: #138673; /* Change border color on hover */
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
            transition: background 0.3s ease;
        }

        button:hover {
            background: linear-gradient(135deg, #138673, #0d5a4d);
            transform: scale(1.05)
        }

        label {
            font-size: 0.95rem;
            color: #00ffcc; /* Neon color */
            margin-bottom: 5px;
            display: block;
        }

        .file-radio, .folder-radio {
            margin: 5px 15px 10px 0;
        }

        .result-container {
            margin-top: 0;
            padding: 15px;
            background: rgba(255, 255, 255, 0.1);
            border: 1px solid #ddd;
            border-radius: 8px;
            max-height: 200px;
            overflow-y: auto;
            width: 100%;
            box-shadow: 0 4px 10px rgba(0, 0, 0, 0.1);
            z-index: 1;
            opacity: 0;
            transform: translateY(-20px);
            transition: opacity 0.5s ease, transform 0.5s ease;
            display: none;
        }

        .result-container h2 {
            font-size: 1.2rem;
            color: #00ffcc;
            margin-bottom: 10px;
        }

        .result-container ul {
            list-style: none;
            padding-left: 0;
        }

        .result-container li {
            font-size: 0.95rem;
            color: #fff;
            margin-bottom: 10px;
        }

        .result-container pre {
            font-size: 0.85rem;
            background: rgba(255, 255, 255, 0.1);
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
    <<body>
    <div id="particles-js"></div>
    <div class="container">
        <div class="form-container">
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
        <div class="result-container" id="resultContainer">
            <h2>Malware Scan Results</h2>
            <ul id="resultList">
                @if(isset($results) && count($results) > 0)
                    @foreach($results as $result)
                        <li>
                            @if(isset($result['output']))
                                <pre>{{ $result['output'] }}</pre>
                            @endif
                        </li>
                    @endforeach
                @endif
            </ul>
        </div>
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
                    color: "#00ffcc", // Neon color
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
            }
        });

        document.getElementById('folderRadio').addEventListener('change', function() {
            if (this.checked) {
                document.getElementById('fileInputContainer').style.display = 'none';
                document.getElementById('folderInputContainer').style.display = 'block';
            }
        });

        window.onload = function() {
            let resultContainer = document.getElementById('resultContainer');
            if (document.getElementById('resultList').children.length > 0) {
                resultContainer.style.display = "block";
                resultContainer.style.opacity = "1";
                resultContainer.style.transform = "translateY(0)";
            }
        };
    </script>
</body>
</html>
