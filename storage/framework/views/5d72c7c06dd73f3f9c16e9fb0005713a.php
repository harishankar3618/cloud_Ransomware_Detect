<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Malware Detection Tool</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            background-color: #f4f4f4;
        }

        .container {
            background: #fff;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            text-align: center;
            width: 90%;
            max-width: 500px;
        }

        h1 {
            font-size: 1.5em;
            margin-bottom: 20px;
            color: #333;
        }

        input[type="file"] {
            width: 100%;
            padding: 10px;
            margin-bottom: 10px;
            border: 1px solid #ccc;
            border-radius: 4px;
            font-size: 1em;
        }

        button {
            width: 100%;
            padding: 10px;
            background-color: #007BFF;
            border: none;
            color: white;
            border-radius: 4px;
            cursor: pointer;
            font-size: 1em;
            transition: background-color 0.3s ease;
        }

        button:hover {
            background-color: #0056b3;
        }

        .result {
            margin-top: 20px;
            padding: 10px;
            background: #e9ecef;
            border-radius: 4px;
            text-align: left;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Malware Detection Tool</h1>
        <form id="malwareForm" action="<?php echo e(route('malware.detect')); ?>" method="POST" enctype="multipart/form-data">
            <?php echo csrf_field(); ?>
            <input type="file" id="fileInput" name="file" required>
            <button type="submit">Check File</button>
        </form>
        <?php if(isset($result)): ?>
            <div id="result" class="result"><?php echo e($result); ?></div>
        <?php endif; ?>
    </div>
</body>
</html>
<?php /**PATH /Users/ashokpoudel/Documents/Cyber Security/Malware/resources/views/welcome.blade.php ENDPATH**/ ?>