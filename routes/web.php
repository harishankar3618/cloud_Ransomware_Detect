<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\MalwareDetectionController;

// Test route to ensure the basic functionality of the application
Route::get('/test', function() {
    return 'Test route is working!';
});

Route::get('/', [MalwareDetectionController::class, 'welcome'])->name('malware.detect');
Route::post('/', [MalwareDetectionController::class, 'detectMalware']);
Route::post('/ip-scan', [MalwareDetectionController::class, 'scanIp'])->name('ip.scan');
