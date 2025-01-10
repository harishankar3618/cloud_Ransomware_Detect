<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Symfony\Component\Process\Exception\ProcessFailedException;
use Symfony\Component\Process\Process;

class MalwareDetectionController extends Controller
{
    public function welcome()
    {
        return view('welcome');
    }

    public function detectMalware(Request $request)
    {
        $request->validate([
            'uploads' => 'required',
            'uploads.*' => 'file|max:102400|mimes:exe,bin,pdf,docx', // max size 100MB, allow certain types
            'receipt_email' => 'required|email'
        ]);

        $uploadedFiles = $request->file('uploads');
        $receiptEmail = $request->input('receipt_email');
        $pythonScriptPath = base_path('Project/scan_file.py');
        $results = [];

        foreach ($uploadedFiles as $file) {
            // Store files in the uploads directory
            $filePath = $file->storeAs('uploads', $file->getClientOriginalName());

            // Get the absolute path of the uploaded file
            $absoluteFilePath = storage_path('app/private/uploads/' . $filePath);

            // Debugging: Check if file exists at the expected location
            if (!file_exists($absoluteFilePath)) {
                $results[] = [
                    'file' => $file->getClientOriginalName(),
                    'error' => 'File not found at the expected location: ' . $absoluteFilePath
                ];
                continue;
            }

            // If it's a file, process it
            $process = new Process(['sudo', 'python3', $pythonScriptPath, $absoluteFilePath, $receiptEmail]);

            $process->run();

            if (!$process->isSuccessful()) {
                $results[] = [
                    'file' => $file->getClientOriginalName(),
                    'error' => $process->getErrorOutput()
                ];
                continue;
            }

            $results[] = [
                'file' => $file->getClientOriginalName(),
                'output' => $process->getOutput()
            ];

            // Optional: Delete the uploaded file after processing
            if (file_exists($absoluteFilePath)) {
                unlink($absoluteFilePath);
            }
        }

        return view('welcome', [
            'results' => $results
        ]);
    }
}
