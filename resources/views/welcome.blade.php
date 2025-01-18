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
            position: relative;
        }

        /* Tab Styles */
        .tabs {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
        }

        .tab {
            padding: 10px 20px;
            background-color: #fff;
            border: 1px solid #ddd;
            border-radius: 8px;
            cursor: pointer;
            font-size: 1.1rem;
        }

        .tab.active {
            background-color: #ff6f61;
            color: white;
            border-color: #ff6f61;
        }

        /* Tab Content */
        .tab-content {
            display: none;
        }

        .tab-content.active {
            display: block;
        }

        input[type="file"], input[type="text"], input[type="email"] {
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
        }

        /* Result Section */
        .result-container {
            margin-top: 20px;
            padding: 15px;
            background: #f9f9f9;
            border-radius: 10px;
            text-align: left;
            font-size: 0.9em;
            color: #555;
            display: none;
            max-height: 300px;
            overflow-y: auto;
        }

        .result-container.visible {
            display: block;
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
    <div class="container">
        <h1>Ransomewatch</h1>
        <p style="color: #777; margin-bottom: 1rem;">
            A modern and innovative tool to check your files for malware threats or scan an IP address.
        </p>

        <!-- Tabs -->
        <div class="tabs">
            <div class="tab active" data-target="fileScanTab">File Scan</div>
            <div class="tab" data-target="ipScanTab">IP Scan</div>
        </div>

        <!-- Tab Content -->
        <div id="fileScanTab" class="tab-content active">
            <!-- File Scan Form -->
            <form id="malwareForm" action="{{ route('malware.detect') }}" method="POST" enctype="multipart/form-data">
                @csrf
                <div>
                    <label for="uploadType">Choose Upload Type:</label><br>
                    <label>
                        <input type="radio" name="fileOrFolder" value="file" id="fileRadio" checked> File
                    </label>
                    <label>
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

        <div id="ipScanTab" class="tab-content">
            <!-- IP Scan Form -->
            <form id="ipScanForm">
                @csrf
                <input type="text" name="ip_address" id="ip_address" placeholder="Enter IP Address" required>
                <button type="submit">Scan IP</button>
            </form>

            <!-- Display IP Scan Results -->
            <div id="ipScanResults" class="result-container"></div>
        </div>

    </div>

    <script>
        // JavaScript to handle tab switching
        const tabs = document.querySelectorAll('.tab');
        const tabContents = document.querySelectorAll('.tab-content');

        tabs.forEach(tab => {
            tab.addEventListener('click', () => {
                const target = tab.dataset.target;

                // Remove active class from all tabs
                tabs.forEach(t => t.classList.remove('active'));
                tab.classList.add('active');

                // Hide all tab contents
                tabContents.forEach(content => content.classList.remove('active'));
                document.getElementById(target).classList.add('active');
            });
        });

        // JavaScript to handle radio button changes for file/folder upload
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

        // Handle IP Scan AJAX submission
        document.getElementById('ipScanForm').addEventListener('submit', function (e) {
            e.preventDefault();

            const ipAddress = document.getElementById('ip_address').value;
            const csrfToken = document.querySelector('input[name="_token"]').value;

            fetch('/ip-scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-TOKEN': csrfToken
                },
                body: JSON.stringify({ ip_address: ipAddress })
            })
            .then(response => response.json())
            .then(data => {
                const resultContainer = document.getElementById('ipScanResults');
                if (data.success) {
                    resultContainer.innerHTML = `<h2>IP Scan Results</h2><pre>${JSON.stringify(data.results, null, 2)}</pre>`;
                    resultContainer.classList.add('visible');
                } else {
                    resultContainer.innerHTML = `<p>Error: ${data.error}</p>`;
                    resultContainer.classList.add('visible');
                }
            })
            .catch(error => {
                console.error('Error:', error);
            });
        });
    </script>
</body>
</html>
