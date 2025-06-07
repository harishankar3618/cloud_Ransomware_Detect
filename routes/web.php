<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\MalwareDetectionController;

// Test route to ensure the basic functionality of the application
Route::get('/test', function() {
    return 'Test route is working!';
});

// Home page: show upload/scan form
Route::get('/', [MalwareDetectionController::class, 'welcome'])->name('home');

// File/folder malware scan submission
Route::post('/malware-detect', [MalwareDetectionController::class, 'detectMalware'])->name('malware.detect');

// IP address scan submission
Route::post('/ip-scan', [MalwareDetectionController::class, 'scanIp'])->name('ip.scan');
